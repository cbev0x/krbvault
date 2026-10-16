"""A small unlock agent, in the spirit of ssh-agent / aws-vault.

After one ``unlock`` the agent holds the vault's DEK in memory and serves it
over a 0600 unix socket for a bounded TTL, so you don't retype the passphrase
on every command. The socket is per-vault and same-user only (filesystem
permissions are the trust boundary, exactly as with ssh-agent).

Protocol (newline-delimited over the unix socket):
    client -> "GET\n"      server -> "OK <hex-dek>\n" | "NO\n"
    client -> "PING\n"     server -> "PONG\n"
    client -> "KILL\n"     server -> "BYE\n"  (then exits)
"""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path
from typing import Optional

from . import config

_RECV = 4096


def query(store: Path) -> Optional[bytes]:
    """Return the DEK from a running agent for this vault, or None."""
    sock_path = config.agent_socket_path(store)
    if not sock_path.exists():
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(str(sock_path))
        s.sendall(b"GET\n")
        resp = s.recv(_RECV).strip()
        s.close()
    except OSError:
        return None
    if resp.startswith(b"OK "):
        try:
            return bytes.fromhex(resp[3:].decode())
        except ValueError:
            return None
    return None


def is_running(store: Path) -> bool:
    sock_path = config.agent_socket_path(store)
    if not sock_path.exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(str(sock_path))
        s.sendall(b"PING\n")
        ok = s.recv(_RECV).strip() == b"PONG"
        s.close()
        return ok
    except OSError:
        # stale socket
        try:
            sock_path.unlink()
        except OSError:
            pass
        return False


def stop(store: Path) -> bool:
    sock_path = config.agent_socket_path(store)
    if not sock_path.exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(str(sock_path))
        s.sendall(b"KILL\n")
        s.recv(_RECV)
        s.close()
    except OSError:
        pass
    try:
        sock_path.unlink()
    except OSError:
        pass
    return True


def _serve(sock_path: Path, dek_hex: str, ttl: int) -> None:
    if sock_path.exists():
        try:
            sock_path.unlink()
        except OSError:
            pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    os.chmod(str(sock_path), 0o600)
    srv.listen(8)
    deadline = time.monotonic() + ttl if ttl > 0 else None
    try:
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                srv.settimeout(remaining)
            else:
                srv.settimeout(None)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                break
            with conn:
                try:
                    cmd = conn.recv(_RECV).strip()
                except OSError:
                    continue
                if cmd == b"GET":
                    conn.sendall(b"OK " + dek_hex.encode() + b"\n")
                elif cmd == b"PING":
                    conn.sendall(b"PONG\n")
                elif cmd == b"KILL":
                    conn.sendall(b"BYE\n")
                    break
                else:
                    conn.sendall(b"NO\n")
    finally:
        srv.close()
        try:
            sock_path.unlink()
        except OSError:
            pass


def start(store: Path, dek: bytes, ttl: int = 28800) -> None:
    """Fork a detached agent holding ``dek`` for ``ttl`` seconds (default 8h)."""
    sock_path = config.agent_socket_path(store)
    if is_running(store):
        stop(store)
    dek_hex = dek.hex()

    # double-fork to detach from the controlling terminal
    pid = os.fork()
    if pid > 0:
        os.waitpid(pid, 0)  # reap the first child promptly
        # give the grandchild a moment to bind the socket
        for _ in range(50):
            if sock_path.exists():
                break
            time.sleep(0.02)
        return
    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        os._exit(0)
    # grandchild: detach stdio and serve
    try:
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            try:
                os.dup2(devnull, fd)
            except OSError:
                pass
    except OSError:
        pass
    try:
        _serve(sock_path, dek_hex, ttl)
    finally:
        os._exit(0)
