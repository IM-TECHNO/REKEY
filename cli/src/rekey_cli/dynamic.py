"""Dynamic database accounts: ask for one, use it, let it expire (or revoke it)."""

import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlencode

from rekey_cli.api import Api, CliError

_SSLMODE = {"disable": "disable", "require": "require", "verify-full": "verify-full"}


def request_creds(api: Api, base: str, role: str, ttl_minutes: int | None) -> dict[str, Any]:
    body = {"ttl_minutes": ttl_minutes} if ttl_minutes else {}
    out: dict[str, Any] = api.json(
        "POST", f"{base}/dynamic/{quote(role, safe='')}/creds", json=body
    )
    return out


def revoke(api: Api, base: str, role: str, lease_id: str) -> None:
    api.request(
        "DELETE", f"{base}/dynamic/{quote(role, safe='')}/leases/{quote(lease_id, safe='')}"
    )


def renew(
    api: Api, base: str, role: str, lease_id: str, ttl_minutes: int | None, note: str = ""
) -> dict[str, Any]:
    """Extend an account. Answers {"status": "renewed", ...} or {"status": "open", "request_id"}."""
    body: dict[str, Any] = {"note": note} if note else {}
    if ttl_minutes:
        body["ttl_minutes"] = ttl_minutes
    out: dict[str, Any] = api.json(
        "POST",
        f"{base}/dynamic/{quote(role, safe='')}/leases/{quote(lease_id, safe='')}/renew",
        json=body,
    )
    return out


def parse_time(value: str) -> datetime:
    when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def lease_expiry(api: Api, base: str, role: str, lease_id: str) -> datetime | None:
    """When the account now ends, or None if it is gone."""
    rows = api.json("GET", f"{base}/dynamic/{quote(role, safe='')}/leases")
    for row in rows:
        if row["id"] == lease_id:
            return parse_time(str(row["expires_at"]))
    return None


def keep_alive(  # noqa: PLR0913
    api: Api,
    base: str,
    role: str,
    lease_id: str,
    ttl_minutes: int | None,
    stop: threading.Event,
    say: Callable[[str], None],
    *,
    margin_seconds: float,
    poll_seconds: float = 15.0,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Renew the account whenever it is close to ending, until `stop` is set.

    It looks at the real expiry each round, so an approval that arrives later is noticed. It gives
    up (once, with a message) when the server says renewal is off or the longest life is reached.
    """
    waiting = False
    while not stop.wait(poll_seconds):
        try:
            expiry = lease_expiry(api, base, role, lease_id)
            if expiry is None:
                say("the account is gone; nothing left to renew")
                return
            if (expiry - now()).total_seconds() > margin_seconds:
                waiting = False
                continue
            if waiting:
                continue
            out = renew(api, base, role, lease_id, ttl_minutes)
            waiting = out.get("status") == "open"
            if waiting:
                say(f"renewal needs approval (request {out['request_id']}); still waiting")
        except CliError as exc:
            say(f"could not renew the account: {exc}")
            if str(exc)[:3] in {"403", "404", "409", "422"}:  # a rule, not a hiccup: stop asking
                return


def child_env(c: dict[str, Any]) -> dict[str, str]:
    """Environment variables for a program: the usual client variables plus generic DB_* ones."""
    host, port, user, pw = str(c["host"]), str(c["port"]), str(c["username"]), str(c["password"])
    db = str(c.get("database") or "")
    env = {"DB_HOST": host, "DB_PORT": port, "DB_USER": user, "DB_PASSWORD": pw, "DB_NAME": db}
    if c.get("kind") == "mysql":
        env |= {"MYSQL_HOST": host, "MYSQL_TCP_PORT": port, "MYSQL_USER": user, "MYSQL_PWD": pw}
        if db:
            env["MYSQL_DATABASE"] = db
    else:
        env |= {"PGHOST": host, "PGPORT": port, "PGUSER": user, "PGPASSWORD": pw, "PGDATABASE": db}
        env["PGSSLMODE"] = _SSLMODE.get(str(c.get("ssl")), "require")
    return env


def url_for(c: dict[str, Any]) -> str:
    scheme = "mysql" if c.get("kind") == "mysql" else "postgresql"
    user, pw = quote(str(c["username"]), safe=""), quote(str(c["password"]), safe="")
    db = quote(str(c.get("database") or ""), safe="")
    query = (
        f"?{urlencode({'sslmode': _SSLMODE.get(str(c.get('ssl')), 'require')})}"
        if scheme == "postgresql"
        else ""
    )
    return f"{scheme}://{user}:{pw}@{c['host']}:{c['port']}/{db}{query}"


def render(c: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(c, indent=2, default=str)
    if fmt == "url":
        return url_for(c)
    if fmt == "dotenv":
        lines = []
        for k, v in child_env(c).items():
            escaped = v.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{k}="{escaped}"')
        return "\n".join(lines)
    raise CliError("--format must be dotenv, json or url")
