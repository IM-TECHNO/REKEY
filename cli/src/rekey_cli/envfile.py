"""Reading a .env file for `rekey import`. Errors name a line number, never the line's content."""

import re

from rekey_cli.api import CliError

_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "$": "$"}


def _double_quoted(text: str, lineno: int) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
        elif c == '"':
            rest = text[i + 1 :].strip()
            if rest and not rest.startswith("#"):
                raise CliError(f"line {lineno}: unexpected text after the closing quote")
            return "".join(out)
        else:
            out.append(c)
            i += 1
    raise CliError(f"line {lineno}: unterminated double quote")


def _single_quoted(text: str, lineno: int) -> str:
    end = text.find("'")
    if end < 0:
        raise CliError(f"line {lineno}: unterminated single quote")
    rest = text[end + 1 :].strip()
    if rest and not rest.startswith("#"):
        raise CliError(f"line {lineno}: unexpected text after the closing quote")
    return text[:end]


def _value(raw: str, lineno: int) -> str:
    raw = raw.lstrip()
    if raw.startswith('"'):
        return _double_quoted(raw[1:], lineno)
    if raw.startswith("'"):
        return _single_quoted(raw[1:], lineno)
    # Unquoted: a ` #` starts a comment, a `#` inside the value (a URL fragment, say) does not.
    m = re.search(r"\s#", raw)
    return (raw[: m.start()] if m else raw).strip()


def parse(text: str) -> tuple[dict[str, str], int]:
    """Return (values, number of repeated keys). A repeated key keeps its last value, as a
    shell sourcing the file would. Multi-line quoted values are not supported."""
    out: dict[str, str] = {}
    repeats = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if lineno == 1:
            stripped = stripped.removeprefix("﻿")
        if not stripped or stripped.startswith("#"):
            continue
        stripped = stripped.removeprefix("export ").lstrip()
        key, sep, raw = stripped.partition("=")
        key = key.strip()
        if not sep or not _KEY.fullmatch(key):
            raise CliError(f"line {lineno}: expected NAME=value")
        if key in out:
            repeats += 1
        out[key] = _value(raw, lineno)
    return out, repeats
