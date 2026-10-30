"""Auto-unseal: let an external key service hold the key that unseals Rekey.

Normally a person has to enter enough shares after every start. With auto-unseal the key-encryption
key (KEK) is stored *wrapped* (encrypted) by a key service you run or rent: HashiCorp Vault /
OpenBao Transit, or AWS KMS. At start the server asks the service to unwrap it and unseals itself. A
stolen copy of the database or disk is still useless, because opening the wrapped KEK needs a
request the key service will answer only for this server. What is given up is that a person's
share is no longer needed on every start: whoever can make the key service answer (and read the
database) can unseal. The shares keep working as the break-glass way in. See docs/AUTO-UNSEAL.md.

Failure never blocks the server: if the key service is down or refuses, it stays sealed, the shares
still work, and a background task retries every 30 seconds. An explicit seal (POST /v1/sys/seal)
pauses auto-unseal until the next restart, so a deliberate seal sticks.

Adding another provider (GCP KMS, Azure Key Vault) means one more class with `wrap` and `unwrap`
and a branch in `check_config` and `build_provider`.
"""

import asyncio
import base64
import contextlib
import hashlib
import hmac
import importlib
import importlib.util
import logging
import re
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from rekey import audit
from rekey.config import Settings
from rekey.crypto import Keyring, SealConfig
from rekey.crypto import envelope as _envelope
from rekey.models import AutoUnseal, SealRow

logger = logging.getLogger("rekey.autounseal")
ACTOR = "auto-unseal"
_CONTEXT = _envelope.encode_context("rekey", "auto-unseal", "kek", 1)
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_MOUNT = re.compile(r"^[A-Za-z0-9_.-]{1,64}(/[A-Za-z0-9_.-]{1,64}){0,3}$")
_TIMEOUT = 10.0


class AutoUnsealError(Exception):
    """A key service problem. The message is safe to show: it never holds a key or a token."""


class NotConfigured(AutoUnsealError):
    """Auto-unseal is off in the server's settings (nothing to ask)."""


class Provider(Protocol):
    name: str
    key_ref: str  # which key wraps the KEK; not a secret

    async def wrap(self, plaintext: bytes, context: bytes) -> bytes: ...

    async def unwrap(self, blob: bytes, context: bytes) -> bytes: ...


# ---- Vault / OpenBao Transit --------------------------------------------------------------


class TransitProvider:
    """Encrypt and decrypt with a Transit key over HTTPS. The token only needs those two paths."""

    name = "transit"

    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None) -> None:
        self._s = settings
        self._http = http
        parsed = urlparse(settings.auto_unseal_addr)
        self._base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        self._mount = settings.auto_unseal_mount.strip("/")
        self._key = settings.auto_unseal_key
        self.key_ref = f"{parsed.netloc}:{self._mount}/{self._key}"[:300]

    def _token(self) -> str:
        s = self._s
        if s.auto_unseal_token_file:
            try:
                with open(s.auto_unseal_token_file, encoding="utf-8") as fh:
                    token = fh.read().strip()
            except OSError:
                raise AutoUnsealError("cannot read the token file") from None
        else:
            token = s.auto_unseal_token
        if not token:
            raise AutoUnsealError("the key service token is empty")
        return token

    async def _post(self, op: str, payload: dict[str, str]) -> dict[str, Any]:
        headers = {"X-Vault-Token": self._token()}
        if self._s.auto_unseal_namespace:
            headers["X-Vault-Namespace"] = self._s.auto_unseal_namespace
        url = f"{self._base}/v1/{self._mount}/{op}/{self._key}"
        client = self._http or httpx.AsyncClient()
        try:
            resp = await client.post(
                url, json=payload, headers=headers, timeout=_TIMEOUT, follow_redirects=False
            )
        except httpx.HTTPError as exc:
            raise AutoUnsealError(
                f"could not reach the key service ({exc.__class__.__name__})"
            ) from None
        finally:
            if self._http is None:
                await client.aclose()
        if resp.status_code != 200:
            raise AutoUnsealError(f"the key service answered HTTP {resp.status_code}")
        try:
            data = resp.json()["data"]
        except (ValueError, KeyError, TypeError):
            raise AutoUnsealError("the key service sent an answer Rekey cannot read") from None
        if not isinstance(data, dict):
            raise AutoUnsealError("the key service sent an answer Rekey cannot read")
        return data

    async def wrap(self, plaintext: bytes, context: bytes) -> bytes:
        # Transit only takes a context for "derived" keys, so bind it ourselves: the value that is
        # encrypted starts with a hash of the context, checked again on the way back.
        bound = hashlib.sha256(context).digest() + plaintext
        data = await self._post("encrypt", {"plaintext": base64.b64encode(bound).decode()})
        cipher = data.get("ciphertext")
        if not isinstance(cipher, str) or not cipher:
            raise AutoUnsealError("the key service sent an answer Rekey cannot read")
        return cipher.encode()

    async def unwrap(self, blob: bytes, context: bytes) -> bytes:
        data = await self._post("decrypt", {"ciphertext": blob.decode("utf-8", "replace")})
        try:
            bound = base64.b64decode(str(data["plaintext"]), validate=True)
        except (KeyError, ValueError):
            raise AutoUnsealError("the key service sent an answer Rekey cannot read") from None
        digest, plain = bound[:32], bound[32:]
        if not hmac.compare_digest(digest, hashlib.sha256(context).digest()):
            raise AutoUnsealError("the wrapped key does not belong to this use")
        return plain


# ---- AWS KMS ------------------------------------------------------------------------------


def _have_boto3() -> bool:
    return importlib.util.find_spec("boto3") is not None


class AwsKmsProvider:
    """AWS KMS Encrypt/Decrypt (boto3 is an optional extra: `pip install rekey-server[aws]`)."""

    name = "aws-kms"

    def __init__(self, settings: Settings, client: Any = None) -> None:
        self._s = settings
        self._client = client
        self.key_ref = settings.auto_unseal_key[:300]

    def _kms(self) -> Any:
        if self._client is None:
            if not _have_boto3():
                raise AutoUnsealError(
                    "AWS KMS needs the boto3 package (install rekey-server with the aws extra)"
                )
            boto3 = importlib.import_module("boto3")
            self._client = boto3.client("kms", region_name=self._s.auto_unseal_region or None)
        return self._client

    @staticmethod
    def _ctx(context: bytes) -> dict[str, str]:
        return {"rekey": base64.b64encode(context).decode()}

    async def wrap(self, plaintext: bytes, context: bytes) -> bytes:
        try:
            resp = await asyncio.to_thread(
                self._kms().encrypt,
                KeyId=self._s.auto_unseal_key,
                Plaintext=plaintext,
                EncryptionContext=self._ctx(context),
            )
            blob = resp["CiphertextBlob"]
        except AutoUnsealError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AutoUnsealError(
                f"AWS KMS refused the request ({exc.__class__.__name__})"
            ) from None
        return bytes(blob)

    async def unwrap(self, blob: bytes, context: bytes) -> bytes:
        try:
            resp = await asyncio.to_thread(
                self._kms().decrypt,
                CiphertextBlob=blob,
                KeyId=self._s.auto_unseal_key,
                EncryptionContext=self._ctx(context),
            )
            plain = resp["Plaintext"]
        except AutoUnsealError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AutoUnsealError(
                f"AWS KMS refused the request ({exc.__class__.__name__})"
            ) from None
        return bytes(plain)


# ---- configuration ------------------------------------------------------------------------


def check_config(settings: Settings) -> None:
    """Fail loudly at start when auto-unseal is half configured (raises RuntimeError)."""
    mode = settings.auto_unseal
    if mode == "off":
        return
    if settings.dev_unseal_file:
        raise RuntimeError(
            "REKEY_AUTO_UNSEAL and REKEY_DEV_UNSEAL_FILE cannot be used together: choose one"
        )
    if mode == "transit":
        addr = settings.auto_unseal_addr
        parsed = urlparse(addr)
        loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if not addr or not parsed.hostname:
            raise RuntimeError("REKEY_AUTO_UNSEAL=transit needs REKEY_AUTO_UNSEAL_ADDR")
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise RuntimeError("REKEY_AUTO_UNSEAL_ADDR must be an https URL")
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path.strip("/")
        ):
            raise RuntimeError(
                "REKEY_AUTO_UNSEAL_ADDR must be just scheme, host and port (no path or credentials)"
            )
        if not _NAME.match(settings.auto_unseal_key) or set(settings.auto_unseal_key) == {"."}:
            raise RuntimeError("REKEY_AUTO_UNSEAL=transit needs REKEY_AUTO_UNSEAL_KEY (a key name)")
        mount = settings.auto_unseal_mount.strip("/")
        if not _MOUNT.match(mount) or any(set(p) == {"."} for p in mount.split("/")):
            raise RuntimeError("REKEY_AUTO_UNSEAL_MOUNT is not a valid mount path")
        if bool(settings.auto_unseal_token) == bool(settings.auto_unseal_token_file):
            raise RuntimeError(
                "set exactly one of REKEY_AUTO_UNSEAL_TOKEN and REKEY_AUTO_UNSEAL_TOKEN_FILE"
            )
    elif mode == "aws-kms":
        if not settings.auto_unseal_key:
            raise RuntimeError("REKEY_AUTO_UNSEAL=aws-kms needs REKEY_AUTO_UNSEAL_KEY")
        if not _have_boto3():
            raise RuntimeError(
                "REKEY_AUTO_UNSEAL=aws-kms needs the boto3 package (the rekey-server aws extra)"
            )


def build_provider(settings: Settings, http: httpx.AsyncClient | None) -> Provider | None:
    if settings.auto_unseal == "transit":
        return TransitProvider(settings, http)
    if settings.auto_unseal == "aws-kms":
        return AwsKmsProvider(settings)
    return None


def get_provider(app: Any) -> Provider | None:
    """The configured provider (tests can set `app.state.autounseal_provider` instead)."""
    override: Provider | None = getattr(app.state, "autounseal_provider", None)
    if override is not None:
        return override
    return build_provider(app.state.settings, getattr(app.state, "http", None))


def fingerprint(check_blob: bytes) -> str:
    return hashlib.sha256(check_blob).hexdigest()


# ---- operations ---------------------------------------------------------------------------


async def _wrap_verified(provider: Provider, ring: Keyring) -> tuple[bytes, bytes]:
    """Wrap the KEK, unwrap it again and compare: a broken key service is caught before saving."""
    kek = ring.export_kek()
    wrapped = await provider.wrap(kek, _CONTEXT)
    back = await provider.unwrap(wrapped, _CONTEXT)
    if not hmac.compare_digest(back, kek):
        raise AutoUnsealError("the key service did not return the key it was given")
    return wrapped, ring.kek_check()


async def enable(app: Any, db: AsyncSession, ring: Keyring, actor: str) -> AutoUnseal:
    """Wrap the unsealed server's KEK with the configured provider and save it."""
    provider = get_provider(app)
    if provider is None:
        raise NotConfigured("auto-unseal is not configured (REKEY_AUTO_UNSEAL is off)")
    seal = await db.get(SealRow, 1)
    if seal is None:
        raise NotConfigured("not initialized")
    wrapped, check = await _wrap_verified(provider, ring)
    row = await db.get(AutoUnseal, 1)
    if row is None:
        row = AutoUnseal(id=1)
        db.add(row)
    row.provider, row.key_ref = provider.name, provider.key_ref
    row.wrapped_kek, row.kek_check = wrapped, check
    row.seal_fingerprint = fingerprint(seal.check_blob)
    row.created_by = actor
    await db.commit()
    app.state.autounseal_paused = False
    return row


async def disable(db: AsyncSession) -> bool:
    result = await db.execute(delete(AutoUnseal).where(AutoUnseal.id == 1))
    await db.commit()
    return bool(result.rowcount)  # type: ignore[attr-defined]


async def rewrap_after_rekey(app: Any, db: AsyncSession, new_ring: Keyring) -> str:
    """The KEK changed: wrap the new one. Returns "off", "rewrapped" or "disabled" (on failure)."""
    row = await db.get(AutoUnseal, 1)
    if row is None:
        return "off"
    try:
        provider = get_provider(app)
        if provider is None:
            raise AutoUnsealError("auto-unseal is no longer configured")
        seal = await db.get(SealRow, 1)
        if seal is None:
            raise AutoUnsealError("not initialized")
        wrapped, check = await _wrap_verified(provider, new_ring)
        row.provider, row.key_ref = provider.name, provider.key_ref
        row.wrapped_kek, row.kek_check = wrapped, check
        row.seal_fingerprint = fingerprint(seal.check_blob)
        await db.commit()
        return "rewrapped"
    except Exception as exc:  # noqa: BLE001
        logger.warning("auto-unseal turned off after a rekey (%s)", exc.__class__.__name__)
        await db.rollback()
        await disable(db)
        return "disabled"


def _fail(app: Any, message: str) -> None:
    """Log a start-up/retry failure once per distinct message, not every 30 seconds."""
    if getattr(app.state, "autounseal_last_error", None) != message:
        app.state.autounseal_last_error = message
        logger.warning("auto-unseal: %s; the server stays sealed (shares still work)", message)


async def stale_reason(app: Any, db: AsyncSession, row: AutoUnseal) -> str:
    """Why the stored wrapped key must not be used, or "" if it matches this configuration."""
    provider = get_provider(app)
    if provider is None:
        return "auto-unseal is not configured"
    if row.provider != provider.name or row.key_ref != provider.key_ref:
        return "the configured key service or key differs from the one that wrapped the key"
    seal = await db.get(SealRow, 1)
    if seal is None or row.seal_fingerprint != fingerprint(seal.check_blob):
        return "the root key was replaced after the key was wrapped"
    return ""


async def try_unseal(app: Any) -> bool:
    """Unseal through the key service. Never raises; True when the server ends up unsealed."""
    settings = app.state.settings
    if settings.auto_unseal == "off" or getattr(app.state, "autounseal_paused", False):
        return False
    current: Keyring | None = app.state.keyring
    if current is not None and not current.sealed:
        return True
    try:
        async with app.state.sessionmaker() as db:
            row = await db.get(AutoUnseal, 1)
            seal = await db.get(SealRow, 1)
            if row is None or seal is None:
                return False  # nothing was ever enabled (or the server is not initialised yet)
            reason = await stale_reason(app, db, row)
            wrapped, check = row.wrapped_kek, row.kek_check
            config = SealConfig(
                seal.threshold, seal.shares, seal.check_blob, seal.share_hashes or b""
            )
        if reason:
            _fail(app, f"ignoring the stored key: {reason}")
            return False
        provider = get_provider(app)
        assert provider is not None  # noqa: S101 (stale_reason checked it)
        kek = await provider.unwrap(wrapped, _CONTEXT)
        ring = app.state.keyring or Keyring(config)  # keep partial shares someone is entering
        ring.load_kek(kek, check)
        app.state.keyring = ring
    except AutoUnsealError as exc:
        _fail(app, str(exc))
        return False
    except Exception as exc:  # noqa: BLE001 - including a key service that returned a wrong key
        _fail(app, f"could not unseal ({exc.__class__.__name__})")
        return False
    app.state.autounseal_last_error = None
    logger.info("auto-unseal: unsealed through the key service")
    with contextlib.suppress(Exception):
        await audit.record(app.state.sessionmaker, actor=ACTOR, action="sys.unseal")
    return True


async def run_forever(
    app: Any, *, poll_seconds: float = 30.0, stop: asyncio.Event | None = None
) -> None:
    """While sealed, keep trying (the key service may come up after Rekey). Stops once unsealed."""
    stop = stop or asyncio.Event()
    while not stop.is_set():
        try:
            if await try_unseal(app):
                return
            ring: Keyring | None = app.state.keyring
            if ring is not None and not ring.sealed:
                return  # a person unsealed it with shares
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad round must not stop the retries
            logger.exception("auto-unseal round failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), poll_seconds)


async def describe(app: Any, db: AsyncSession) -> dict[str, Any]:
    """State for the API and the Security page."""
    settings = app.state.settings
    row = await db.get(AutoUnseal, 1)
    out: dict[str, Any] = {
        "configured": settings.auto_unseal,
        "enabled": row is not None,
        "provider": row.provider if row else "",
        "key_ref": row.key_ref if row else "",
        "since": row.created_at if row else None,
        "stale": "",
        "paused": bool(getattr(app.state, "autounseal_paused", False)),
    }
    if row is not None:
        out["stale"] = await stale_reason(app, db, row)
    return out
