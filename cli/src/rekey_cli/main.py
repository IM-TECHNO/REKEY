import functools
import json
import os
import subprocess  # noqa: S404 (running the user's own command is the point of `run`)
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from rekey_cli import api as api_mod
from rekey_cli import config, login
from rekey_cli.api import Api, CliError

app = typer.Typer(
    help="Rekey: fetch and inject secrets.", no_args_is_help=True, add_completion=False
)

Project = Annotated[
    str, typer.Option("--project", "-p", envvar="REKEY_PROJECT", help="Project slug.")
]
EnvOpt = Annotated[str, typer.Option("--env", "-e", envvar="REKEY_ENV", help="Environment slug.")]
PathOpt = Annotated[str, typer.Option("--path", help="Secret path.")]

_PROJECT_FILE = ".rekey.json"


def _defaults() -> dict[str, str]:
    """Optional `.rekey.json` in the current directory: {"project": "...", "env": "..."}."""
    try:
        raw = json.loads(Path(_PROJECT_FILE).read_text(encoding="utf-8"))
        return {k: str(v) for k, v in raw.items() if k in ("project", "env")}
    except (OSError, ValueError):
        return {}


def _need(value: str, key: str, flag: str) -> str:
    value = value or _defaults().get(key, "")
    if not value:
        raise CliError(f"missing {flag} (or set it in {_PROJECT_FILE})")
    return value


def _client() -> Api:
    return api_mod.resolve(api_mod.make_http())


def _guard[**P](fn: Callable[P, None]) -> Callable[P, None]:
    """Turn CliError into a clean message and exit code 1."""

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> None:
        try:
            fn(*args, **kwargs)
        except CliError as exc:
            typer.echo(f"rekey: {exc}", err=True)
            raise typer.Exit(1) from exc

    return wrapper


def _base(project: str, env: str) -> str:
    return (
        f"/v1/projects/{_need(project, 'project', '--project')}/envs/{_need(env, 'env', '--env')}"
    )


@app.command("login")
@_guard
def login_cmd(
    server: Annotated[
        str, typer.Option(help="Rekey server URL, e.g. https://rekey.example.com")
    ] = "",
) -> None:
    """Sign in with GitLab in your browser."""
    cfg = config.load()
    url = api_mod.normalise_server(server or os.environ.get("REKEY_SERVER") or cfg.server or "")
    if not url or url == "https://":
        raise CliError("pass --server https://...")
    result = login.login(
        Api(url, "", api_mod.make_http()), announce=lambda m: typer.echo(m, err=True)
    )
    config.save(config.Config(server=url, token=result["token"], expires_at=result["expires_at"]))
    typer.echo(f"Signed in as {result['identity']} (session until {result['expires_at']})")


@app.command()
@_guard
def logout() -> None:
    """Revoke the session on the server and forget it locally."""
    cfg = config.load()
    if cfg.token and cfg.server:
        try:
            Api(api_mod.normalise_server(cfg.server), cfg.token, api_mod.make_http()).request(
                "POST", "/v1/auth/logout"
            )
        except CliError:
            pass  # already expired or unreachable: still clear the local copy
    if cfg.token:
        config.clear_token()
    typer.echo("Signed out.")


@app.command()
@_guard
def whoami() -> None:
    """Show who you are signed in as."""
    me = _client().json("GET", "/v1/auth/whoami")
    typer.echo(me["name"] + (" (superadmin)" if me["superadmin"] else ""))


@app.command()
@_guard
def get(
    name: str,
    project: Project = "",
    env: EnvOpt = "",
    path: PathOpt = "/",
    version: Annotated[int, typer.Option(help="Specific version; default latest.")] = 0,
) -> None:
    """Print one secret's value."""
    if "/" in name:
        raise CliError("a secret name cannot contain '/'; use --path for the folder")
    params: dict[str, str | int] = {"path": path}
    if version:
        params["version"] = version
    out = _client().json("GET", f"{_base(project, env)}/secrets/{name}", params=params)
    typer.echo(out["value"])


@app.command("set")
@_guard
def set_cmd(
    name: str,
    project: Project = "",
    env: EnvOpt = "",
    path: PathOpt = "/",
    kind: Annotated[str, typer.Option(help="plain, sealed or bool.")] = "plain",
) -> None:
    """Create or update a secret. The value is read from stdin or a hidden prompt (never argv)."""
    stream = typer.get_text_stream("stdin")
    if stream.isatty():
        value = typer.prompt(f"Value for {name}", hide_input=True)
    else:
        value = stream.read().removesuffix("\n")
    out = _client().json(
        "PUT",
        f"{_base(project, env)}/secrets/{name}",
        params={"path": path},
        json={"value": value, "kind": kind},
    )
    if "change_request" in out:
        # A protected environment: the change waits for a second person to approve it.
        typer.echo(
            f"{name}: submitted for approval as change request {out['change_request']} "
            "(nothing has changed yet)"
        )
        return
    typer.echo(f"{name}: version {out['version']}")


@app.command("list")
@_guard
def list_cmd(
    project: Project = "",
    env: EnvOpt = "",
    prefix: Annotated[str, typer.Option(help="Path prefix.")] = "/",
) -> None:
    """List secret names (never values)."""
    for item in _client().json("GET", f"{_base(project, env)}/secrets", params={"prefix": prefix}):
        typer.echo(f"{item['path'].rstrip('/')}/{item['name']}\tv{item['version']}\t{item['kind']}")


@app.command("requests")
@_guard
def requests_cmd(
    all_: Annotated[bool, typer.Option("--all", help="Include decided requests.")] = False,
) -> None:
    """List change requests you can see (your own, and ones you can approve)."""
    rows = _client().json(
        "GET", "/v1/change-requests", params={"status": "all" if all_ else "open"}
    )
    if not rows:
        typer.echo("No change requests.")
    for r in rows:
        flag = "approve?" if r["can_decide"] else ("yours" if r["is_author"] else "")
        typer.echo(
            f"{r['id']}\t{r['status']}\t{r['project']}/{r['environment']}\t"
            f"{r['action']} {r['path'].rstrip('/')}/{r['name']}\tby {r['author']}\t{flag}"
        )


def _decide(change_id: str, verb: str, note: str) -> None:
    out = _client().json("POST", f"/v1/change-requests/{change_id}/{verb}", json={"note": note})
    suffix = f" (secret is now version {out['version']})" if out.get("version") else ""
    typer.echo(f"{change_id}: {out['status']}{suffix}")


@app.command()
@_guard
def approve(
    change_id: str, note: Annotated[str, typer.Option(help="Optional comment.")] = ""
) -> None:
    """Approve a change request. You cannot approve your own."""
    _decide(change_id, "approve", note)


@app.command()
@_guard
def reject(
    change_id: str, note: Annotated[str, typer.Option(help="Why it was rejected.")] = ""
) -> None:
    """Reject a change request."""
    _decide(change_id, "reject", note)


def _fetch(project: str, env: str, path: str) -> dict[str, str]:
    out: dict[str, str] = _client().json(
        "GET", f"{_base(project, env)}/export", params={"path": path}
    )
    return out


@app.command()
@_guard
def export(
    project: Project = "",
    env: EnvOpt = "",
    path: PathOpt = "/",
    fmt: Annotated[str, typer.Option("--format", help="dotenv or json.")] = "dotenv",
) -> None:
    """Print secrets as a .env file or JSON. Prefer `run`; this writes plaintext to stdout."""
    secrets = _fetch(project, env, path)
    if fmt == "json":
        typer.echo(json.dumps(secrets, indent=2))
    elif fmt == "dotenv":
        for key, value in secrets.items():
            escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            typer.echo(f'{key}="{escaped}"')
    else:
        raise CliError("--format must be dotenv or json")


@app.command(context_settings={"allow_interspersed_args": False})
@_guard
def run(
    command: Annotated[list[str], typer.Argument(help="Command to run, after --")],
    project: Project = "",
    env: EnvOpt = "",
    path: PathOpt = "/",
) -> None:
    """Run COMMAND with the environment's secrets as environment variables.

    Example: rekey run -p app -e dev -- npm start
    """
    secrets = _fetch(project, env, path)
    child = {k: v for k, v in os.environ.items() if k not in ("REKEY_TOKEN", "REKEY_JWT")}
    child.update(secrets)  # secrets win over inherited variables
    try:
        result = subprocess.run(command, env=child, check=False)  # noqa: S603
    except FileNotFoundError as exc:
        raise CliError(f"command not found: {command[0]}") from exc
    sys.exit(result.returncode)


if __name__ == "__main__":
    app()
