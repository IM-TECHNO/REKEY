"""Thin HTTP client for the Rekey API."""

import os
from typing import Any
from urllib.parse import urlparse

import httpx

from rekey_cli import config


class CliError(Exception):
    """A problem to show the user plainly, without a traceback."""


def make_http() -> httpx.Client:
    return httpx.Client(timeout=15.0, follow_redirects=False)


def normalise_server(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    loopback = host in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not loopback and os.environ.get("REKEY_INSECURE") != "1":
        raise CliError("refusing to send credentials over plain http; use https:// for the server")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


class Api:
    def __init__(self, server: str, token: str, http: httpx.Client) -> None:
        self.server = server
        self.token = token
        self.http = http

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = self.http.request(method, self.server + path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise CliError(f"cannot reach {self.server}: {exc.__class__.__name__}") from exc
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", "")
            except ValueError:
                detail = ""
            hint = " (run `rekey login`)" if resp.status_code == 401 else ""
            raise CliError(f"{resp.status_code} {detail or resp.reason_phrase}{hint}")
        if 300 <= resp.status_code < 400:
            raise CliError(f"unexpected redirect ({resp.status_code}); check the path")
        return resp

    def json(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self.request(method, path, **kwargs)
        try:
            return resp.json()
        except ValueError as exc:
            raise CliError(f"{self.server} did not return JSON for {path}") from exc


def resolve(http: httpx.Client) -> Api:
    """Build a client from, in order: REKEY_TOKEN, a GitLab CI ID token, or the saved login."""
    cfg = config.load()
    server = os.environ.get("REKEY_SERVER") or cfg.server
    if not server:
        raise CliError("no server configured: run `rekey login --server https://...`")
    server = normalise_server(server)

    if token := os.environ.get("REKEY_TOKEN"):
        return Api(server, token, http)
    if jwt_token := os.environ.get(
        "REKEY_JWT"
    ):  # `id_tokens: REKEY_JWT: {aud: rekey}` in GitLab CI
        anon = Api(server, "", http)
        return Api(
            server, anon.json("POST", "/v1/auth/jwt/login", json={"jwt": jwt_token})["token"], http
        )
    if not cfg.token:
        raise CliError("not logged in: run `rekey login`")
    if cfg.expired():
        raise CliError("session expired: run `rekey login`")
    return Api(server, cfg.token, http)
