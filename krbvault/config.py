"""Store discovery and runtime paths.

A vault is a single ``<engagement>.kvault`` SQLite file. It is looked up in
this order:

1. ``--store PATH`` (explicit)
2. ``$KRBVAULT_STORE``
3. a ``.krbvault/`` directory found by walking up from the current directory
   (so ``cd`` into an engagement folder "just works")
4. ``$KRBVAULT_HOME`` (default ``~/.krbvault``)

The active ccache that ``KRB5CCNAME`` points at lives at a single stable path
(``~/.krbvault/active.ccache``) so the shell export can be set once.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

APP_DIR_NAME = ".krbvault"
DEFAULT_ENGAGEMENT = "default"
STORE_EXT = ".kvault"


def home_dir() -> Path:
    d = Path(os.environ.get("KRBVAULT_HOME", str(Path.home() / APP_DIR_NAME)))
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def find_local_dir(start: Optional[Path] = None) -> Optional[Path]:
    start = (start or Path.cwd()).resolve()
    for d in [start, *start.parents]:
        cand = d / APP_DIR_NAME
        if cand.is_dir():
            return cand
    return None


def resolve_store(engagement: Optional[str] = None,
                  explicit: Optional[str] = None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    if os.environ.get("KRBVAULT_STORE"):
        return Path(os.environ["KRBVAULT_STORE"]).expanduser().resolve()
    eng = (engagement or os.environ.get("KRBVAULT_ENGAGEMENT")
           or DEFAULT_ENGAGEMENT)
    base = find_local_dir() or home_dir()
    return (base / f"{eng}{STORE_EXT}").resolve()


def _run_dir(store: Path) -> Path:
    key = hashlib.sha256(str(store).encode()).hexdigest()[:12]
    base = home_dir() / "run"
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    d = base / key
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def active_ccache_path() -> Path:
    """Stable path the user points KRB5CCNAME at (set once in the shell rc)."""
    return home_dir() / "active.ccache"


def export_ccache_path(store: Path, ident: str) -> Path:
    """Per-identity ccache for --export / parallel-shell use."""
    safe = "".join(c if c.isalnum() or c in "._@-" else "_" for c in ident)
    return _run_dir(store) / f"ccache-{safe}.ccache"


def agent_socket_path(store: Path) -> Path:
    return _run_dir(store) / "agent.sock"


def shell_env_line() -> str:
    return f'export KRB5CCNAME="{active_ccache_path()}"'


# --- small JSON config (per-realm KDC, etc.) --------------------------------

def config_path() -> Path:
    return home_dir() / "config.json"


def load_config() -> dict:
    p = config_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_config(cfg: dict) -> None:
    p = config_path()
    p.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def get_dc(realm: Optional[str]) -> Optional[str]:
    if not realm:
        return None
    return load_config().get("dc", {}).get(realm.upper())


def set_dc(realm: str, ip: str) -> None:
    cfg = load_config()
    cfg.setdefault("dc", {})[realm.upper()] = ip
    save_config(cfg)


def unset_dc(realm: str) -> bool:
    cfg = load_config()
    removed = cfg.get("dc", {}).pop(realm.upper(), None) is not None
    save_config(cfg)
    return removed
