"""OIDC login and GitLab CI ID-token verification.

Only asymmetric signatures are accepted (never `none` or HMAC), the issuer and audience are
always checked, and signing keys come from the issuer's published JWKS.
"""

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt

from rekey.config import Settings

ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384"]
_JWKS_TTL = 600.0
_LEEWAY = 30


class OidcError(Exception):
    """The provider rejected us, or a token failed verification."""


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    return verifier, s256(verifier)


def challenge_matches(verifier: str, challenge: str) -> bool:
    return hmac.compare_digest(s256(verifier).encode(), challenge.encode())


class Provider:
    def __init__(self, settings: Settings, http: httpx.AsyncClient) -> None:
        self._s = settings
        self._http = http
        self._meta: dict[str, Any] | None = None
        self._keys: list[dict[str, Any]] | None = None
        self._keys_at = 0.0
        self._last_forced = float("-inf")
        self._min_refresh = 30.0  # seconds between forced key refreshes

    @property
    def enabled(self) -> bool:
        return bool(self._s.oidc_issuer)

    async def metadata(self) -> dict[str, Any]:
        if self._meta is None:
            parsed = urlparse(self._s.oidc_issuer)
            if parsed.scheme != "https" and parsed.hostname not in (
                "localhost",
                "127.0.0.1",
                "::1",
            ):
                raise OidcError("the OIDC issuer must use https")
            url = self._s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            try:
                resp = await self._http.get(url)
                resp.raise_for_status()
                meta: dict[str, Any] = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise OidcError("cannot reach the identity provider") from exc
            if str(meta.get("issuer", "")).rstrip("/") != self._s.oidc_issuer.rstrip("/"):
                raise OidcError("issuer mismatch in provider metadata")
            self._meta = meta
        return self._meta

    async def _jwks(self, *, force: bool = False) -> list[dict[str, Any]]:
        if force or self._keys is None or time.monotonic() - self._keys_at > _JWKS_TTL:
            meta = await self.metadata()
            try:
                resp = await self._http.get(meta["jwks_uri"])
                resp.raise_for_status()
                self._keys = list(resp.json()["keys"])
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                raise OidcError("cannot fetch signing keys") from exc
            self._keys_at = time.monotonic()
        return self._keys

    @staticmethod
    def _find(keys: list[dict[str, Any]], kid: str) -> Any | None:
        for jwk in keys:
            if jwk.get("kid") == kid:
                try:
                    return jwt.PyJWK(jwk).key
                except jwt.PyJWTError:
                    return None
        return None

    async def verify(
        self, token: str, *, audience: str, nonce: str | None = None
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OidcError("malformed token") from exc
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in ALGORITHMS or not isinstance(kid, str):
            raise OidcError("unsupported token header")
        key = self._find(await self._jwks(), kid)
        if key is None and time.monotonic() - self._last_forced >= self._min_refresh:
            # The provider may have rotated its keys. Refetch, but at most once per interval: a
            # stream of tokens with made-up key ids must not become a stream of requests to GitLab.
            self._last_forced = time.monotonic()
            key = self._find(await self._jwks(force=True), kid)
        if key is None:
            raise OidcError("unknown signing key")
        meta = await self.metadata()
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=audience,
                issuer=str(meta["issuer"]),
                leeway=_LEEWAY,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("token verification failed") from exc
        if nonce is not None and not hmac.compare_digest(
            str(claims.get("nonce", "")).encode(), nonce.encode()
        ):
            raise OidcError("nonce mismatch")
        return claims

    async def authorize_url(self, *, state: str, nonce: str, challenge: str) -> str:
        meta = await self.metadata()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._s.oidc_client_id,
                "redirect_uri": self._s.oidc_redirect_uri,
                "scope": self._s.oidc_scopes,
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{meta['authorization_endpoint']}?{query}"

    async def exchange_code(self, code: str, verifier: str) -> str:
        meta = await self.metadata()
        try:
            resp = await self._http.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._s.oidc_redirect_uri,
                    "client_id": self._s.oidc_client_id,
                    "client_secret": self._s.oidc_client_secret,
                    "code_verifier": verifier,
                },
            )
            resp.raise_for_status()
            id_token = resp.json()["id_token"]
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise OidcError("code exchange failed") from exc
        if not isinstance(id_token, str):
            raise OidcError("provider returned no id_token")
        return id_token
