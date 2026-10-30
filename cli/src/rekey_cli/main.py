import functools
import json
import os
import subprocess  # noqa: S404 (running the user's own command is the point of `run`)
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Annotated

import typer
import typer.main

from rekey_cli import api as api_mod
from rekey_cli import config, envfile, login
from rekey_cli import dynamic as dynamic_mod
from rekey_cli import scan as scan_mod
from rekey_cli.api import Api, CliError

app = typer.Typer(
    help="Rekey: fetch and inject secrets.", no_args_is_help=True, add_completion=False
)


def _show_version(show: bool) -> None:
    if show:
        try:
            typer.echo(metadata.version("rekey-cli"))
        except metadata.PackageNotFoundError:
            typer.echo("unknown")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_show_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    pass


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


@app.command("help")
def help_cmd(
    command: Annotated[
        list[str] | None, typer.Argument(help="Command to describe, e.g. `dynamic run`.")
    ] = None,
) -> None:
    """Show help for rekey, or for one command: rekey help import."""
    # Same text as `rekey <command> --help`; an unknown command is a usage error.
    typer.main.get_command(app).main(
        args=[*(command or []), "--help"], prog_name="rekey", standalone_mode=True
    )


def _headless() -> bool:
    """No usable browser on this machine: an SSH session, or Linux with no desktop (where Python
    would otherwise start a text-mode browser that cannot finish the sign-in)."""
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        return True
    return sys.platform.startswith("linux") and not (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    )


@app.command("login")
@_guard
def login_cmd(
    server: Annotated[
        str, typer.Option(help="Rekey server URL, e.g. https://rekey.example.com")
    ] = "",
    no_browser: Annotated[
        bool,
        typer.Option(
            "--no-browser",
            help="Print a link to open on any device, then paste the code it shows. "
            "Used automatically over SSH or without a desktop.",
        ),
    ] = False,
) -> None:
    """Sign in with GitLab (over SSH: open a link elsewhere and paste the code)."""
    cfg = config.load()
    url = api_mod.normalise_server(server or os.environ.get("REKEY_SERVER") or cfg.server or "")
    if not url or url == "https://":
        raise CliError("pass --server https://...")
    paste = None
    if no_browser or _headless():
        paste = lambda: typer.prompt("Paste the code shown after signing in")  # noqa: E731
    result = login.login(
        Api(url, "", api_mod.make_http()), announce=lambda m: typer.echo(m, err=True), paste=paste
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


@app.command("import")
@_guard
def import_cmd(
    file: Annotated[Path, typer.Argument(help="A .env file to load.")],
    project: Project = "",
    env: EnvOpt = "",
    path: PathOpt = "/",
    kind: Annotated[str, typer.Option(help="plain, sealed or bool, for every secret.")] = "plain",
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Replace secrets that already exist.")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would happen; change nothing.")
    ] = False,
) -> None:
    """Load the NAME=value lines of a .env file as secrets.

    Prints names and outcomes only, never a value. Existing secrets are left alone unless
    --overwrite. On a protected environment each change waits for approval.
    Example: rekey import auth/.env -p app -e prod --path /auth --dry-run
    """
    try:
        text = file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CliError(f"cannot read {file}: {exc.__class__.__name__}") from exc
    try:
        values, repeats = envfile.parse(text)
    except CliError as exc:
        raise CliError(f"{file}: {exc}") from exc
    if kind not in ("plain", "sealed", "bool"):
        raise CliError("--kind must be plain, sealed or bool")
    where = "/" + path.strip("/")
    client = _client()
    base = _base(project, env)
    existing = {
        s["name"]
        for s in client.json("GET", f"{base}/secrets", params={"prefix": where})
        if s["path"] == where
    }
    if repeats:
        typer.echo(f"note: {repeats} repeated name(s); the last value of each is used", err=True)
    counts = {"added": 0, "replaced": 0, "kept": 0, "empty": 0, "queued": 0, "failed": 0}
    for name, value in values.items():
        if not value:
            outcome = "empty"  # an empty value is a placeholder, not a secret
        elif name in existing and not overwrite:
            outcome = "kept"
        elif dry_run:
            outcome = "replaced" if name in existing else "added"
        else:
            try:
                out = client.json(
                    "PUT",
                    f"{base}/secrets/{name}",
                    params={"path": where},
                    json={"value": value, "kind": kind},
                )
                if "change_request" in out:
                    outcome = "queued"
                else:
                    outcome = "replaced" if name in existing else "added"
            except CliError as exc:
                typer.echo(f"{name}: failed ({exc})", err=True)
                outcome = "failed"
        counts[outcome] += 1
        if outcome != "failed":
            label = {"kept": "exists, kept", "empty": "empty, skipped"}.get(outcome, outcome)
            if dry_run and outcome in ("added", "replaced"):
                label = "would be " + label
            typer.echo(f"{name}: {label}")
    summary = ", ".join(f"{n} {k}" for k, n in counts.items() if n)
    typer.echo(f"{'Dry run: ' if dry_run else ''}{summary or 'nothing to do'}.")
    if counts["failed"]:
        raise typer.Exit(1)


dynamic_app = typer.Typer(
    help="Short-lived database accounts, created on request and removed on expiry.",
    no_args_is_help=True,
)
app.add_typer(dynamic_app, name="dynamic")
Role = Annotated[str, typer.Argument(help="Dynamic role name.")]
Ttl = Annotated[
    int | None, typer.Option("--ttl", min=1, help="Minutes the account lives (role default).")
]


@dynamic_app.command("creds")
@_guard
def dynamic_creds(
    role: Role,
    project: Project = "",
    env: EnvOpt = "",
    ttl: Ttl = None,
    fmt: Annotated[str, typer.Option("--format", help="dotenv, json or url.")] = "dotenv",
) -> None:
    """Create an account and print its credentials. They are shown once; Rekey keeps no copy."""
    creds = dynamic_mod.request_creds(_client(), _base(project, env), role, ttl)
    typer.echo(dynamic_mod.render(creds, fmt))
    typer.echo(f"rekey: lease {creds['lease_id']} expires {creds['expires_at']}", err=True)


@dynamic_app.command("run", context_settings={"allow_interspersed_args": False})
@_guard
def dynamic_run(
    role: Role,
    command: Annotated[list[str], typer.Argument(help="Command to run, after --")],
    project: Project = "",
    env: EnvOpt = "",
    ttl: Ttl = None,
    renew: Annotated[
        bool,
        typer.Option("--renew", help="Keep extending the account while COMMAND runs (if allowed)."),
    ] = False,
) -> None:
    """Run COMMAND with a fresh account in its environment, then remove the account.

    Sets PGHOST/PGUSER/PGPASSWORD (or MYSQL_*) and DB_HOST/DB_USER/DB_PASSWORD/DB_NAME.
    Example: rekey dynamic run -p app -e dev readonly -- psql -c 'select 1'
    """
    if command and command[0] == "--":  # the separator arrives as an argument after ROLE
        command = command[1:]
    if not command:
        raise CliError("give the command to run after the role, e.g. -- psql -c 'select 1'")
    api, base = _client(), _base(project, env)
    creds = dynamic_mod.request_creds(api, base, role, ttl)
    child = {k: v for k, v in os.environ.items() if k not in ("REKEY_TOKEN", "REKEY_JWT")}
    child.update(dynamic_mod.child_env(creds))
    stop = threading.Event()
    if renew:
        life = (
            dynamic_mod.parse_time(str(creds["expires_at"])) - datetime.now(UTC)
        ).total_seconds()
        threading.Thread(
            target=dynamic_mod.keep_alive,
            args=(
                api,
                base,
                role,
                creds["lease_id"],
                ttl,
                stop,
                lambda m: typer.echo(f"rekey: {m}", err=True),
            ),
            kwargs={
                "margin_seconds": max(5.0, life / 4),
                "poll_seconds": max(1.0, min(15.0, life / 8)),
            },
            daemon=True,
        ).start()
    try:
        result = subprocess.run(command, env=child, check=False)  # noqa: S603
    except FileNotFoundError as exc:
        raise CliError(f"command not found: {command[0]}") from exc
    finally:
        stop.set()
        try:  # the account is useless once the command is done: take it away now
            dynamic_mod.revoke(api, base, role, creds["lease_id"])
        except CliError as exc:
            typer.echo(
                f"rekey: could not revoke the account early ({exc}); it expires on its own",
                err=True,
            )
    sys.exit(result.returncode)


@dynamic_app.command("revoke")
@_guard
def dynamic_revoke(
    role: Role,
    lease_id: Annotated[str, typer.Argument(help="Lease id printed by `creds`.")],
    project: Project = "",
    env: EnvOpt = "",
) -> None:
    """Remove an account before it expires."""
    dynamic_mod.revoke(_client(), _base(project, env), role, lease_id)


@dynamic_app.command("renew")
@_guard
def dynamic_renew(
    role: Role,
    lease_id: Annotated[str, typer.Argument(help="Lease id printed by `creds`.")],
    project: Project = "",
    env: EnvOpt = "",
    ttl: Ttl = None,
    note: Annotated[str, typer.Option(help="Why, for the person approving.")] = "",
) -> None:
    """Extend an account (or ask for it to be extended, if the role needs approval)."""
    out = dynamic_mod.renew(_client(), _base(project, env), role, lease_id, ttl, note)
    if out["status"] == "renewed":
        typer.echo(f"rekey: account now expires {out['expires_at']}")
    else:
        typer.echo(f"rekey: waiting for approval, request {out['request_id']}")


@dynamic_app.command("renewals")
@_guard
def dynamic_renewals(
    all_: Annotated[bool, typer.Option("--all", help="Include decided requests.")] = False,
) -> None:
    """List renewal requests you can see (your own, and ones you can decide)."""
    rows = _client().json("GET", "/v1/lease-renewals", params={"status": "all" if all_ else "open"})
    if not rows:
        typer.echo("No renewal requests.")
    for r in rows:
        flag = "decide?" if r["can_decide"] else ("yours" if r["is_author"] else "")
        typer.echo(
            f"{r['id']}	{r['status']}	{r['project']}/{r['environment']}	{r['role']} "
            f"{r['username']}	+{r['ttl_minutes']}m	by {r['author']}	{flag}"
        )


def _decide_renewal(renewal_id: str, verb: str, note: str) -> None:
    out = _client().json("POST", f"/v1/lease-renewals/{renewal_id}/{verb}", json={"note": note})
    until = f" (account now expires {out['expires_at']})" if out.get("expires_at") else ""
    typer.echo(f"{renewal_id}: {out['status']}{until}")


@dynamic_app.command("approve")
@_guard
def dynamic_approve(
    renewal_id: str, note: Annotated[str, typer.Option(help="Optional comment.")] = ""
) -> None:
    """Approve a renewal request. You cannot approve your own."""
    _decide_renewal(renewal_id, "approve", note)


@dynamic_app.command("reject")
@_guard
def dynamic_reject(
    renewal_id: str, note: Annotated[str, typer.Option(help="Why it was rejected.")] = ""
) -> None:
    """Reject a renewal request."""
    _decide_renewal(renewal_id, "reject", note)


@dynamic_app.command("cancel")
@_guard
def dynamic_cancel(renewal_id: str) -> None:
    """Withdraw a renewal request you made."""
    _decide_renewal(renewal_id, "cancel", "")


@dynamic_app.command("leases")
@_guard
def dynamic_leases(role: Role, project: Project = "", env: EnvOpt = "") -> None:
    """List your live accounts for a role (all of them, for a superadmin)."""
    rows = _client().json("GET", f"{_base(project, env)}/dynamic/{role}/leases")
    for r in rows:
        typer.echo(f"{r['id']}  {r['username']}  {r['identity']}  expires {r['expires_at']}")


@app.command()
def scan(
    paths: Annotated[
        list[str] | None, typer.Argument(help="Files or folders to scan (default: .). - is stdin.")
    ] = None,
    project: Project = "",
    env: EnvOpt = "",
    stdin: Annotated[
        bool, typer.Option("--stdin", help="Also scan piped input, e.g. a log.")
    ] = False,
    min_length: Annotated[
        int, typer.Option(min=1, help="Skip secrets shorter than this (they match too often).")
    ] = 8,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="Glob to skip; repeatable.")
    ] = None,
    no_encodings: Annotated[
        bool, typer.Option("--no-encodings", help="Only look for the exact value.")
    ] = False,
) -> None:
    """Fail if any secret value of an environment appears in files or piped text.

    Exit 0 clean, 1 something found, 2 error. Never prints a value.
    Example: rekey scan -p app -e dev . ; ./build.sh 2>&1 | rekey scan -p app -e dev --stdin
    """
    wanted = list(paths or [])
    use_stdin = stdin or "-" in wanted
    wanted = [p for p in wanted if p != "-"] or ([] if use_stdin else ["."])
    try:
        secrets, report = scan_mod.fetch_secrets(_client(), _base(project, env), min_length)
        data = typer.get_binary_stream("stdin").read() if use_stdin else None
        scan_mod.scan(
            secrets,
            report,
            paths=wanted,
            stdin_data=data,
            excludes=list(exclude or []),
            encodings=not no_encodings,
        )
    except CliError as exc:
        typer.echo(f"rekey: {exc}", err=True)
        raise typer.Exit(2) from exc
    scan_mod.render(report, min_length, typer.echo, lambda m: typer.echo(m, err=True))
    raise typer.Exit(0 if report.clean else 1)


if __name__ == "__main__":
    app()
