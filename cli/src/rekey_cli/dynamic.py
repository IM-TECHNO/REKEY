"""Dynamic database accounts: ask for one, use it, let it expire (or revoke it)."""

import json
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
