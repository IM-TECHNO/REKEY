"""Seal/unseal and the key hierarchy: root key -> KEK -> environment keys -> secret values."""

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rekey.crypto import envelope, shamir
from rekey.crypto.errors import DecryptionError, InvalidShares, SealedError

_CHECK_PLAINTEXT = b"rekey-seal-check"


@dataclass(frozen=True)
class SealConfig:
    """Non-secret state persisted by the server; safe to store in the database.

    `share_hashes` is the SHA-256 of every share, concatenated in share-index order (32 bytes
    each). It lets the server reject a wrong or forged share the moment it arrives, so nobody who
    can reach the (unauthenticated) unseal endpoint can overwrite or reset an unseal in progress.
    A share is 32 uniformly random bytes plus an index, so its hash reveals nothing usable.
    Empty means "not recorded" (a seal record from before this existed): no early check.
    """

    threshold: int
    shares: int
    check: bytes
    share_hashes: bytes = b""


def _derive(root: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=envelope.KEY_LEN, salt=None, info=info).derive(
        root
    )


def _check_key(root: bytes) -> bytes:
    return _derive(root, b"rekey/seal-check/v1")


def _kek(root: bytes) -> bytes:
    return _derive(root, b"rekey/kek/v1")


def initialize(threshold: int = 3, shares: int = 5) -> tuple[list[bytes], SealConfig]:
    """Create a new root key and return (unseal shares, config to persist).

    The root key itself is discarded; it only exists again after enough shares are combined.
    """
    root = os.urandom(envelope.KEY_LEN)
    parts = shamir.split(root, threshold, shares)
    check = envelope.seal(_check_key(root), _CHECK_PLAINTEXT, b"seal-check")
    hashes = b"".join(hashlib.sha256(p).digest() for p in parts)
    return parts, SealConfig(threshold=threshold, shares=shares, check=check, share_hashes=hashes)


class Keyring:
    """Holds the KEK in memory while unsealed. Everything else is derived on demand."""

    def __init__(self, config: SealConfig) -> None:
        self._config = config
        self._pending: dict[int, bytes] = {}
        self._kek: bytearray | None = None

    @property
    def sealed(self) -> bool:
        return self._kek is None

    @property
    def progress(self) -> tuple[int, int]:
        return len(self._pending), self._config.threshold

    def unseal(self, share: bytes) -> bool:
        """Add one share. Returns True once the keyring is unsealed."""
        if not self.sealed:
            return True
        if len(share) < 2 or share[0] == 0:
            raise InvalidShares("malformed share")
        hashes = self._config.share_hashes
        if hashes:
            # Check this share on its own, before it can touch the shares already entered.
            index = share[0]
            expected = hashes[(index - 1) * 32 : index * 32]
            if len(expected) != 32 or not hmac.compare_digest(
                hashlib.sha256(share).digest(), expected
            ):
                raise InvalidShares("not a valid share")
        self._pending[share[0]] = share
        if len(self._pending) < self._config.threshold:
            return False

        parts = list(self._pending.values())
        self._pending.clear()
        root = shamir.combine(parts)
        try:
            envelope.open_(_check_key(root), self._config.check, b"seal-check")
        except DecryptionError as exc:
            raise InvalidShares("shares do not reconstruct the root key") from exc
        self._kek = bytearray(_kek(root))
        return True

    def seal(self) -> None:
        """Wipe the KEK and any partial shares."""
        if self._kek is not None:
            for i in range(len(self._kek)):
                self._kek[i] = 0
        self._kek = None
        self._pending.clear()

    def _require_kek(self) -> bytes:
        if self._kek is None:
            raise SealedError("keyring is sealed")
        return bytes(self._kek)

    # Environment keys: stored wrapped, bound to the environment id and key version.

    def new_env_key(self, env_id: str, version: int) -> bytes:
        """Generate a fresh environment key and return it wrapped by the KEK."""
        return envelope.seal(
            self._require_kek(),
            os.urandom(envelope.KEY_LEN),
            envelope.encode_context("env-key", env_id, version),
        )

    def _open_env_key(self, wrapped: bytes, env_id: str, version: int) -> bytes:
        return envelope.open_(
            self._require_kek(), wrapped, envelope.encode_context("env-key", env_id, version)
        )

    def rewrap(self, wrapped: bytes, env_id: str, version: int, new: "Keyring") -> bytes:
        """Move an environment key under another keyring's KEK (root key rotation)."""
        key = self._open_env_key(wrapped, env_id, version)
        return envelope.seal(
            new._require_kek(), key, envelope.encode_context("env-key", env_id, version)
        )

    # Pending values (change requests): bound to the environment and the request id.

    def encrypt_pending(
        self,
        wrapped_env_key: bytes,
        *,
        env_id: str,
        env_key_version: int,
        request_id: str,
        value: bytes,
    ) -> bytes:
        key = self._open_env_key(wrapped_env_key, env_id, env_key_version)
        return envelope.seal(
            key, value, envelope.encode_context("change-request", env_id, request_id)
        )

    def decrypt_pending(
        self,
        wrapped_env_key: bytes,
        *,
        env_id: str,
        env_key_version: int,
        request_id: str,
        blob: bytes,
    ) -> bytes:
        key = self._open_env_key(wrapped_env_key, env_id, env_key_version)
        return envelope.open_(
            key, blob, envelope.encode_context("change-request", env_id, request_id)
        )

    # Secret values: bound to project, environment, path, key and version.

    def encrypt_value(
        self,
        wrapped_env_key: bytes,
        *,
        env_id: str,
        env_key_version: int,
        path: str,
        name: str,
        version: int,
        value: bytes,
    ) -> bytes:
        key = self._open_env_key(wrapped_env_key, env_id, env_key_version)
        context = envelope.encode_context("secret", env_id, path, name, version)
        return envelope.seal(key, value, context)

    def decrypt_value(
        self,
        wrapped_env_key: bytes,
        *,
        env_id: str,
        env_key_version: int,
        path: str,
        name: str,
        version: int,
        blob: bytes,
    ) -> bytes:
        key = self._open_env_key(wrapped_env_key, env_id, env_key_version)
        context = envelope.encode_context("secret", env_id, path, name, version)
        return envelope.open_(key, blob, context)
