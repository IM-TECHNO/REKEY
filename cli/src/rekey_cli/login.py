"""Browser login: GitLab OIDC through the server, finished on a loopback listener.

The CLI keeps a secret verifier; the server only ever sees its hash. The one-time code that
reaches this machine's loopback listener is useless to anyone who does not hold the verifier.
"""

import base64
import hashlib
import secrets
import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from rekey_cli.api import Api, CliError

_PAGE = b"<html><body><h3>Rekey: signed in.</h3>You can close this tab.</body></html>"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class _Listener(HTTPServer):
    code: str | None = None


class _Handler(BaseHTTPRequestHandler):
    server: _Listener

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        url = urlparse(self.path)
        code = parse_qs(url.query).get("code", [""])[0]
        if url.path != "/callback" or not code:
            self.send_response(404)
            self.end_headers()
            return
        self.server.code = code
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_PAGE)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # keep the one-time code out of any log


def login(
    api: Api,
    open_browser: Callable[[str], object] = webbrowser.open,
    timeout: float = 180.0,
    announce: Callable[[str], None] = print,
    paste: Callable[[], str] | None = None,
) -> dict[str, str]:
    """Run the browser flow and return the server's {token, expires_at, identity}.

    With `paste`, no browser or listener is used on this machine: the person opens the printed URL
    anywhere, and `paste()` returns the code the server shows them afterwards."""
    verifier, challenge = _pkce()
    if paste is not None:
        url = f"{api.server}/v1/auth/oidc/login?" + urlencode(
            {"mode": "cli", "challenge": challenge}
        )
        announce(f"Open this address in any browser and sign in with GitLab:\n  {url}")
        code = paste().strip()
        if not code:
            raise CliError("no code entered")
        resp = api.json("POST", "/v1/auth/cli/exchange", json={"code": code, "verifier": verifier})
        return {k: str(resp[k]) for k in ("token", "expires_at", "identity")}
    listener = _Listener(("127.0.0.1", 0), _Handler)  # port 0: the OS picks a free port
    listener.timeout = 1.0
    port = listener.server_address[1]
    url = f"{api.server}/v1/auth/oidc/login?" + urlencode(
        {"mode": "cli", "port": port, "challenge": challenge}
    )
    announce(f"Opening your browser to sign in with GitLab.\nIf it does not open, visit:\n  {url}")

    opener = threading.Thread(target=open_browser, args=(url,), daemon=True)
    opener.start()
    waited = 0.0
    try:
        while listener.code is None and waited < timeout:
            listener.handle_request()
            waited += 1.0
    finally:
        listener.server_close()
    if listener.code is None:
        raise CliError("timed out waiting for the browser login")

    resp = api.json(
        "POST", "/v1/auth/cli/exchange", json={"code": listener.code, "verifier": verifier}
    )
    return {k: str(resp[k]) for k in ("token", "expires_at", "identity")}
