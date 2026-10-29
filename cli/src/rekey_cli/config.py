"""Where the CLI keeps its server URL and session token."""

import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class Config:
    server: str = ""
    token: str = ""
    expires_at: str = ""  # ISO-8601, informational; the server is the authority

    def expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            return datetime.fromisoformat(self.expires_at) <= datetime.now(UTC)
        except ValueError:
            return False


def config_path() -> Path:
    override = os.environ.get("REKEY_CONFIG_DIR")
    if override:
        return Path(override) / "config.json"
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "rekey" / "config.json"


def load() -> Config:
    path = config_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return Config(**{k: str(raw.get(k, "")) for k in ("server", "token", "expires_at")})
    except (OSError, ValueError):
        return Config()


def save(cfg: Config) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with owner-only permissions from the start (no window where it is world-readable).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(asdict(cfg), fh)
    if os.name != "nt":
        path.chmod(0o600)


def clear_token() -> None:
    cfg = load()
    cfg.token = ""
    cfg.expires_at = ""
    save(cfg)
