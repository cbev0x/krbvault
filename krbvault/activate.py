"""Make a stored ticket the active one for KRB5CCNAME.

The default flow materializes the chosen ccache to a single stable path
(``~/.krbvault/active.ccache``) that the shell export points at — set once,
and every impacket/nxc call thereafter reads the current selection. Because
the ticket bytes are sealed in the vault, there is no plaintext file to
symlink to, so we write the decrypted bytes to the active path atomically
(0600) and replace in place.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from . import config


def materialize(ccache_bytes: bytes, path: Path) -> Path:
    """Atomically write ccache bytes to ``path`` with 0600 perms."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(ccache_bytes)
        os.replace(str(tmp), str(path))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    os.chmod(str(path), 0o600)
    return path


def set_active(ccache_bytes: bytes) -> Path:
    """Default: write to the stable active path KRB5CCNAME points at."""
    return materialize(ccache_bytes, config.active_ccache_path())


def set_export(ccache_bytes: bytes, store: Path, ident: str) -> Path:
    """Write to a per-identity path for parallel shells; caller prints the
    `export KRB5CCNAME=...` line for `eval`."""
    return materialize(ccache_bytes, config.export_ccache_path(store, ident))


def run_subshell(ccache_bytes: bytes, store: Path, ident: str) -> int:
    """Materialize to a scoped ccache and drop into a subshell with
    KRB5CCNAME set to it; clean up on exit."""
    path = config.export_ccache_path(store, ident)
    materialize(ccache_bytes, path)
    env = dict(os.environ)
    env["KRB5CCNAME"] = str(path)
    shell = os.environ.get("SHELL", "/bin/bash")
    try:
        return subprocess.call([shell], env=env)
    finally:
        try:
            path.unlink()
        except OSError:
            pass
