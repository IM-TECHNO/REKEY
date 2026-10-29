"""A stand-in for GitLab: OIDC discovery, JWKS, token endpoint, and CI ID-token signing."""

import json
import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://gitlab.test"
CLIENT_ID = "rekey-app"


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeIdp:
    def __init__(self) -> None:
        self.key = _new_key()
        self.kid = "key-1"
        self.nonce = ""  # the test copies the nonce from the authorize redirect
        self.user: dict[str, Any] = {
            "sub": "1001",
            "nickname": "alice",
            "email": "alice@example.com",
            "groups_direct": ["acme"],
        }
        self.fail_exchange = False
        self.override: str | None = None  # if set, the token endpoint returns exactly this
        self.requests: list[str] = []

    def rotate(self) -> None:
        self.key = _new_key()
        self.kid = "key-2"

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def sign(
        self,
        claims: dict[str, Any],
        *,
        key: Any = None,
        kid: str | None = None,
        alg: str = "RS256",
    ) -> str:
        return jwt.encode(claims, key or self.key, algorithm=alg, headers={"kid": kid or self.kid})

    def id_token(self, **override: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce,
            **self.user,
        }
        claims.update(override)
        return self.sign(claims)

    def ci_token(
        self,
        project_path: str = "acme/myapp-api",
        ref: str = "main",
        protected: str = "true",
        aud: str = "rekey",
        exp_in: int = 300,
        **extra: Any,
    ) -> str:
        now = int(time.time())
        return self.sign(
            {
                "iss": ISSUER,
                "aud": aud,
                "sub": f"project_path:{project_path}:ref_type:branch:ref:{ref}",
                "iat": now,
                "exp": now + exp_in,
                "project_path": project_path,
                "ref": ref,
                "ref_protected": protected,
                **extra,
            }
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(f"{request.method} {request.url.path}")
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
                    "token_endpoint": f"{ISSUER}/oauth/token",
                    "jwks_uri": f"{ISSUER}/oauth/discovery/keys",
                },
            )
        if path == "/oauth/discovery/keys":
            return httpx.Response(200, json=self.jwks())
        if path == "/oauth/token" and request.method == "POST":
            if self.fail_exchange:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.override or self.id_token()})
        return httpx.Response(404)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
