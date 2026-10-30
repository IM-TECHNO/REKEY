"""`rekey scan`: find the values of your own secrets where they should not be.

Rekey already knows every value in an environment, so instead of guessing at what "looks like" a key
the scanner looks for those exact values (and their base64 and URL-encoded forms) in files and piped
text. A match means a secret leaked into a repository or a job log.

Nothing here ever prints a value, or any part of one: findings name the secret, never its content.
"""

import base64
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import quote, quote_plus

from rekey_cli.api import Api, CliError

MAX_FILE_BYTES = 5 * 1024 * 1024
IGNORE_FILE = ".rekeyscanignore"
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}
_SNIFF = 8192
_MAX_HITS_PER_PATTERN = 50
STDIN_LABEL = "<stdin>"


@dataclass(frozen=True)
class Secret:
    name: str
    path: str
    version: int
    value: str

    @property
    def label(self) -> str:
        return f"{self.name} ({self.path})"


@dataclass(frozen=True)
class Pattern:
    secret: Secret
    form: str  # exact | base64 | url-encoded
    needle: bytes


@dataclass(frozen=True)
class Finding:
    where: str
    line: int
    secret: Secret
    form: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files: int = 0
    stdin: bool = False
    skipped_files: int = 0
    checked: int = 0
    too_short: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.findings


# ---- the secrets ---------------------------------------------------------------------------


def fetch_secrets(api: Api, base: str, min_length: int) -> tuple[list[Secret], Report]:
    """Every secret the caller can read, via the ordinary list + read endpoints."""
    report = Report()
    secrets: list[Secret] = []
    for item in api.json("GET", f"{base}/secrets", params={"prefix": "/"}):
        name, path = str(item["name"]), str(item["path"])
        try:
            out = api.json("GET", f"{base}/secrets/{name}", params={"path": path})
        except CliError as exc:
            # Listed but not readable (a narrower grant): it cannot be scanned for. Anything else,
            # such as a network error or a server fault, must not look like a clean scan.
            if str(exc).startswith(("403 ", "404 ")):
                report.unreadable.append(f"{name} ({path})")
                continue
            raise
        value = str(out["value"])
        if len(value) < max(min_length, 1):
            report.too_short.append(f"{name} ({path})")
            continue
        secrets.append(
            Secret(name, path, int(out.get("version") or item.get("version") or 0), value)
        )
    report.checked = len(secrets)
    return secrets, report


def build_patterns(secrets: list[Secret], encodings: bool) -> list[Pattern]:
    """The exact value, plus base64 and URL-encoded spellings of it."""
    seen: set[tuple[str, bytes]] = set()
    patterns: list[Pattern] = []

    def add(secret: Secret, form: str, text: str) -> None:
        needle = text.encode("utf-8")
        if needle and (secret.name + secret.path, needle) not in seen:
            seen.add((secret.name + secret.path, needle))
            patterns.append(Pattern(secret, form, needle))

    for s in secrets:
        add(s, "exact", s.value)
        if "\n" in s.value:  # the same value in a file saved with Windows line endings
            add(s, "exact", s.value.replace("\r\n", "\n").replace("\n", "\r\n"))
        if not encodings:
            continue
        raw = s.value.encode("utf-8")
        for b64 in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
            add(s, "base64", b64.decode("ascii"))
            add(s, "base64", b64.decode("ascii").rstrip("="))
        add(s, "url-encoded", quote(s.value, safe=""))
        add(s, "url-encoded", quote_plus(s.value))
    return patterns


# ---- scanning one blob of bytes ------------------------------------------------------------


def scan_bytes(where: str, data: bytes, patterns: list[Pattern]) -> list[Finding]:
    found: dict[tuple[int, str, str, str], Finding] = {}
    for p in patterns:
        start = 0
        hits = 0
        while hits < _MAX_HITS_PER_PATTERN:
            at = data.find(p.needle, start)
            if at < 0:
                break
            line = data.count(b"\n", 0, at) + 1  # where the match starts
            key = (line, p.secret.name, p.secret.path, p.form)
            found.setdefault(key, Finding(where, line, p.secret, p.form))
            start = at + len(p.needle)
            hits += 1
    return sorted(found.values(), key=lambda f: (f.line, f.secret.name, f.form))


# ---- which files ---------------------------------------------------------------------------


def _load_ignore(root: Path) -> list[str]:
    try:
        text = (root / IGNORE_FILE).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return [
        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]


def ignored(rel: str, globs: list[str]) -> bool:
    """True if `rel` (posix, relative to the scan root), its name or a parent folder matches."""
    parts = rel.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for glob in globs:
        g = glob.removeprefix("./").rstrip("/")
        if any(fnmatch(x, g) for x in (*prefixes, parts[-1])):
            return True
    return False


def _walk(root: Path, globs: list[str]) -> Iterator[tuple[str, Path]]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        rel_dir = base.relative_to(root).as_posix()
        keep = []
        for d in sorted(dirnames):
            rel = d if rel_dir == "." else f"{rel_dir}/{d}"
            if d not in SKIP_DIRS and not (base / d).is_symlink() and not ignored(rel, globs):
                keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            rel = f if rel_dir == "." else f"{rel_dir}/{f}"
            if ignored(rel, globs):
                continue
            yield rel, base / f


def _read_text_file(path: Path) -> bytes | None:
    """The file's bytes, or None for anything that is not a plain readable text file."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return None if b"\0" in data[:_SNIFF] else data


# ---- the whole run -------------------------------------------------------------------------


def scan(
    secrets: list[Secret],
    report: Report,
    *,
    paths: list[str],
    stdin_data: bytes | None,
    excludes: list[str],
    encodings: bool,
) -> Report:
    patterns = build_patterns(secrets, encodings)
    for raw in paths:
        target = Path(raw)
        if target.is_dir():
            prefix = raw.rstrip("/\\")
            files = _walk(target, [*_load_ignore(target), *excludes])
            shown = [(f"{prefix}/{rel}", p) for rel, p in files]
        elif target.is_file():
            shown = [] if ignored(target.name, excludes) else [(raw, target)]
        else:
            raise CliError(f"no such file or folder: {raw}")
        for label, file in shown:
            data = _read_text_file(file)
            if data is None:
                report.skipped_files += 1
                continue
            report.files += 1
            report.findings.extend(scan_bytes(Path(label).as_posix(), data, patterns))
    if stdin_data is not None:
        report.stdin = True
        report.findings.extend(scan_bytes(STDIN_LABEL, stdin_data, patterns))
    return report


def render(
    report: Report, min_length: int, out: Callable[[str], None], err: Callable[[str], None]
) -> None:
    """Findings go to `out`, the summary to `err`. Names and places only, never a value."""
    for f in report.findings:
        note = "" if f.form == "exact" else f"  [{f.form}]"
        out(f"{f.where}:{f.line}  secret {f.secret.label} v{f.secret.version}{note}")
    scanned = f"{report.files} file{'s' if report.files != 1 else ''}" + (
        " and stdin" if report.stdin else ""
    )
    if report.findings:
        places = len({f.where for f in report.findings})
        err(
            f"Found {len(report.findings)} possible leak{'s' if len(report.findings) != 1 else ''} "
            f"in {places} place{'s' if places != 1 else ''} ({scanned} scanned, "
            f"{report.checked} secrets checked). Treat these secrets as exposed and rotate them."
        )
    else:
        err(f"No secrets found ({scanned} scanned, {report.checked} secrets checked).")
    if report.too_short:
        err(
            f"Skipped {len(report.too_short)} secret(s) shorter than {min_length} characters "
            f"(too many false matches): {', '.join(report.too_short)}"
        )
    if report.unreadable:
        err(
            f"Could not read {len(report.unreadable)} secret(s) with this login, so they were "
            f"not checked: {', '.join(report.unreadable)}"
        )
    if report.skipped_files:
        err(f"Skipped {report.skipped_files} binary, unreadable or oversized file(s).")
