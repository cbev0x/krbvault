"""The encrypted SQLite vault.

Design notes
------------
* One SQLite file per engagement; credential values and ticket bytes are sealed
  with the DEK (envelope encryption, see ``crypto``). This is an at-rest
  secrets store, the same category as a password manager.
* Metadata (principals, SPNs, flags, lifetimes, credential *types*) is stored in
  plaintext columns so ``ls``/``describe`` work without unlocking and stay fast
  to query. The secret-bearing material itself is never readable without the
  passphrase.
* Treat the ``.kvault`` file as sensitive and keep it in the engagement
  workspace; secrets inside are encrypted, metadata is not.
"""
from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple

from . import crypto
from .models import Credential, Identity, IdentityType, Ticket

SCHEMA_VERSION = "1"

_DDL = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB);

CREATE TABLE identities (
    id          INTEGER PRIMARY KEY,
    principal   TEXT NOT NULL,
    realm       TEXT NOT NULL,
    itype       TEXT NOT NULL DEFAULT 'unknown',
    sid         TEXT,
    privileged  INTEGER NOT NULL DEFAULT 0,
    tags        TEXT,                 -- JSON list
    notes       TEXT,
    created_at  TEXT,
    UNIQUE(principal, realm)
);

CREATE TABLE credentials (
    id          INTEGER PRIMARY KEY,
    identity_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    ctype       TEXT NOT NULL,
    enc_value   BLOB NOT NULL,        -- sealed with DEK (aad=cred:<ctype>)
    source      TEXT,
    obtained_at TEXT,
    created_at  TEXT
);

CREATE TABLE tickets (
    id           INTEGER PRIMARY KEY,
    identity_id  INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    client       TEXT,
    client_realm TEXT,
    server       TEXT,
    server_realm TEXT,
    flags        TEXT,                -- JSON list
    key_etype    INTEGER,
    etype_name   TEXT,
    auth_time    TEXT,
    start_time   TEXT,
    end_time     TEXT,
    renew_till   TEXT,
    enc_blob     BLOB NOT NULL,       -- sealed with DEK (aad=ticket)
    source       TEXT,
    created_at   TEXT
);
"""


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class StoreError(Exception):
    pass


class LockedError(StoreError):
    pass


class Store:
    def __init__(self, path: Path, conn: sqlite3.Connection):
        self.path = Path(path)
        self._conn = conn
        self._dek: Optional[bytes] = None

    # --- lifecycle ----------------------------------------------------------

    @classmethod
    def create(cls, path: Path, passphrase: str, engagement: str) -> "Store":
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise StoreError(f"vault already exists: {path}")
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_DDL)

        salt = crypto.new_salt()
        kek = crypto.derive_kek(passphrase, salt)
        dek = crypto.new_dek()
        wrapped = crypto.wrap_dek(kek, dek)
        check = crypto.seal(dek, b"krbvault-ok", "check")

        meta = {
            "schema_version": SCHEMA_VERSION.encode(),
            "engagement": engagement.encode(),
            "created_at": _now().encode(),
            "kdf_salt": salt,
            "kdf_ops": str(crypto.DEFAULT_OPS).encode(),
            "kdf_mem": str(crypto.DEFAULT_MEM).encode(),
            "wrapped_dek": wrapped,
            "dek_check": check,
        }
        conn.executemany("INSERT INTO meta(key, value) VALUES (?, ?)",
                         list(meta.items()))
        conn.commit()
        try:
            path.chmod(0o600)
        except OSError:
            pass
        store = cls(path, conn)
        store._dek = dek
        return store

    @classmethod
    def open(cls, path: Path) -> "Store":
        path = Path(path)
        if not path.exists():
            raise StoreError(f"no vault at {path} (run 'krbvault init' first)")
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA foreign_keys=ON")
        return cls(path, conn)

    def close(self) -> None:
        self._conn.close()

    def _meta(self, key: str) -> Optional[bytes]:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    @property
    def engagement(self) -> str:
        v = self._meta("engagement")
        return v.decode() if v else "?"

    # --- unlocking ----------------------------------------------------------

    def unlock(self, passphrase: str) -> None:
        salt = self._meta("kdf_salt")
        ops = int(self._meta("kdf_ops"))
        mem = int(self._meta("kdf_mem"))
        kek = crypto.derive_kek(passphrase, salt, ops, mem)
        # Unwrapping authenticates the KEK; a wrong passphrase raises BadPassphrase.
        self._dek = crypto.unwrap_dek(kek, self._meta("wrapped_dek"))

    def unlock_with_dek(self, dek: bytes) -> None:
        """Unlock using a DEK supplied by the agent; verified via dek_check."""
        crypto.open_(dek, self._meta("dek_check"), "check")  # raises BadPassphrase
        self._dek = dek

    def derive_dek(self, passphrase: str) -> bytes:
        """Derive+return the DEK without storing it (used to seed the agent)."""
        salt = self._meta("kdf_salt")
        ops = int(self._meta("kdf_ops"))
        mem = int(self._meta("kdf_mem"))
        kek = crypto.derive_kek(passphrase, salt, ops, mem)
        return crypto.unwrap_dek(kek, self._meta("wrapped_dek"))

    @property
    def dek(self) -> bytes:
        if self._dek is None:
            raise LockedError("vault is locked — run 'krbvault unlock' or provide the passphrase")
        return self._dek

    @property
    def locked(self) -> bool:
        return self._dek is None

    def change_passphrase(self, new_passphrase: str) -> None:
        """Re-wrap the DEK under a new passphrase. Stored blobs are untouched."""
        if self.locked:
            raise LockedError("unlock before changing the passphrase")
        salt = crypto.new_salt()
        kek = crypto.derive_kek(new_passphrase, salt)
        wrapped = crypto.wrap_dek(kek, self._dek)
        self._conn.execute("UPDATE meta SET value=? WHERE key='kdf_salt'", (salt,))
        self._conn.execute("UPDATE meta SET value=? WHERE key='wrapped_dek'", (wrapped,))
        self._conn.commit()

    # --- identities ---------------------------------------------------------

    def add_identity(self, principal: str, realm: str,
                     itype: str = IdentityType.UNKNOWN.value,
                     sid: Optional[str] = None, notes: Optional[str] = None,
                     tags: Optional[List[str]] = None) -> Identity:
        realm = realm.upper()
        existing = self.get_identity(f"{principal}@{realm}")
        if existing:
            return existing
        cur = self._conn.execute(
            "INSERT INTO identities(principal, realm, itype, sid, tags, notes, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (principal, realm, itype, sid, json.dumps(tags or []), notes, _now()))
        self._conn.commit()
        return self.get_identity_by_id(cur.lastrowid)

    def set_identity_type(self, identity_id: int, itype: str) -> None:
        self._conn.execute("UPDATE identities SET itype=? WHERE id=?", (itype, identity_id))
        self._conn.commit()

    def _row_to_identity(self, r) -> Identity:
        return Identity(id=r[0], principal=r[1], realm=r[2], itype=r[3],
                        sid=r[4], privileged=bool(r[5]),
                        tags=json.loads(r[6] or "[]"), notes=r[7], created_at=r[8])

    _ID_COLS = "id,principal,realm,itype,sid,privileged,tags,notes,created_at"

    def get_identity_by_id(self, iid: int) -> Optional[Identity]:
        r = self._conn.execute(
            f"SELECT {self._ID_COLS} FROM identities WHERE id=?", (iid,)).fetchone()
        return self._row_to_identity(r) if r else None

    def get_identity(self, upn: str) -> Optional[Identity]:
        if "@" not in upn:
            raise StoreError(f"identity must be principal@REALM, got {upn!r}")
        principal, realm = upn.rsplit("@", 1)
        # AD principals are case-insensitive; match that (realm is normalised upper).
        r = self._conn.execute(
            f"SELECT {self._ID_COLS} FROM identities "
            "WHERE principal=? COLLATE NOCASE AND realm=? COLLATE NOCASE",
            (principal, realm.upper())).fetchone()
        return self._row_to_identity(r) if r else None

    def list_identities(self, realm: Optional[str] = None) -> List[Identity]:
        if realm:
            rows = self._conn.execute(
                f"SELECT {self._ID_COLS} FROM identities WHERE realm=? "
                "ORDER BY realm, principal", (realm.upper(),)).fetchall()
        else:
            rows = self._conn.execute(
                f"SELECT {self._ID_COLS} FROM identities ORDER BY realm, principal").fetchall()
        return [self._row_to_identity(r) for r in rows]

    def realms(self) -> List[str]:
        return [r[0] for r in self._conn.execute(
            "SELECT DISTINCT realm FROM identities ORDER BY realm").fetchall()]

    def delete_identity(self, identity_id: int) -> None:
        self._conn.execute("DELETE FROM identities WHERE id=?", (identity_id,))
        self._conn.commit()

    # --- credentials --------------------------------------------------------

    def add_credential(self, identity_id: int, ctype: str, value: bytes,
                       source: Optional[str] = None,
                       obtained_at: Optional[str] = None) -> int:
        if isinstance(value, str):
            value = value.encode("utf-8")
        enc = crypto.seal(self.dek, value, f"cred:{ctype}")
        # One credential per type per identity: replace any existing of this type.
        self._conn.execute(
            "DELETE FROM credentials WHERE identity_id=? AND ctype=?", (identity_id, ctype))
        cur = self._conn.execute(
            "INSERT INTO credentials(identity_id, ctype, enc_value, source, obtained_at, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (identity_id, ctype, enc, source, obtained_at, _now()))
        self._conn.commit()
        return cur.lastrowid

    def has_credential(self, identity_id: int, ctype: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM credentials WHERE identity_id=? AND ctype=? LIMIT 1",
            (identity_id, ctype)).fetchone() is not None

    def list_credentials(self, identity_id: int) -> List[Credential]:
        """Metadata only — values stay sealed (use reveal_credential)."""
        rows = self._conn.execute(
            "SELECT id, identity_id, ctype, source, obtained_at, created_at "
            "FROM credentials WHERE identity_id=? ORDER BY ctype", (identity_id,)).fetchall()
        return [Credential(id=r[0], identity_id=r[1], ctype=r[2], value=b"",
                           source=r[3], obtained_at=r[4], created_at=r[5]) for r in rows]

    def reveal_credential(self, cred_id: int) -> Tuple[str, bytes]:
        r = self._conn.execute(
            "SELECT ctype, enc_value FROM credentials WHERE id=?", (cred_id,)).fetchone()
        if not r:
            raise StoreError(f"no credential #{cred_id}")
        ctype, enc = r
        return ctype, crypto.open_(self.dek, enc, f"cred:{ctype}")

    def delete_credential(self, cred_id: int) -> None:
        self._conn.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
        self._conn.commit()

    # --- tickets ------------------------------------------------------------

    def add_ticket(self, identity_id: int, t: Ticket) -> int:
        enc = crypto.seal(self.dek, t.blob, "ticket")
        cur = self._conn.execute(
            "INSERT INTO tickets(identity_id, kind, client, client_realm, server, server_realm, "
            "flags, key_etype, etype_name, auth_time, start_time, end_time, renew_till, "
            "enc_blob, source, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (identity_id, t.kind, t.client, t.client_realm, t.server, t.server_realm,
             json.dumps(t.flags), t.key_etype, t.etype_name, t.auth_time, t.start_time,
             t.end_time, t.renew_till, enc, t.source, _now()))
        self._conn.commit()
        return cur.lastrowid

    _TKT_COLS = ("id, identity_id, kind, client, client_realm, server, server_realm, "
                 "flags, key_etype, etype_name, auth_time, start_time, end_time, renew_till, "
                 "source, created_at")

    def _row_to_ticket(self, r) -> Ticket:
        return Ticket(id=r[0], identity_id=r[1], kind=r[2], client=r[3], client_realm=r[4],
                      server=r[5], server_realm=r[6], flags=json.loads(r[7] or "[]"),
                      key_etype=r[8], etype_name=r[9], auth_time=r[10], start_time=r[11],
                      end_time=r[12], renew_till=r[13], source=r[14], created_at=r[15])

    def list_tickets(self, identity_id: Optional[int] = None) -> List[Ticket]:
        """Metadata only — blobs stay sealed (use reveal_ticket)."""
        if identity_id is None:
            rows = self._conn.execute(
                f"SELECT {self._TKT_COLS} FROM tickets ORDER BY end_time DESC").fetchall()
        else:
            rows = self._conn.execute(
                f"SELECT {self._TKT_COLS} FROM tickets WHERE identity_id=? "
                "ORDER BY end_time DESC", (identity_id,)).fetchall()
        return [self._row_to_ticket(r) for r in rows]

    def get_ticket(self, ticket_id: int) -> Optional[Ticket]:
        r = self._conn.execute(
            f"SELECT {self._TKT_COLS} FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        return self._row_to_ticket(r) if r else None

    def reveal_ticket(self, ticket_id: int) -> bytes:
        r = self._conn.execute(
            "SELECT enc_blob FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        if not r:
            raise StoreError(f"no ticket #{ticket_id}")
        return crypto.open_(self.dek, r[0], "ticket")

    def delete_ticket(self, ticket_id: int) -> None:
        self._conn.execute("DELETE FROM tickets WHERE id=?", (ticket_id,))
        self._conn.commit()

    # --- convenience --------------------------------------------------------

    def counts(self, identity_id: int) -> Tuple[int, int]:
        c = self._conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE identity_id=?", (identity_id,)).fetchone()[0]
        t = self._conn.execute(
            "SELECT COUNT(*) FROM tickets WHERE identity_id=?", (identity_id,)).fetchone()[0]
        return c, t

    def find_ticket_by_meta(self, client: str, server: str,
                            auth_time: Optional[str]) -> Optional[int]:
        """Match a ticket by its (plaintext) identifying metadata — used to tell
        which stored ticket the active KRB5CCNAME cache corresponds to."""
        r = self._conn.execute(
            "SELECT id FROM tickets WHERE client=? AND server=? AND auth_time IS ? LIMIT 1",
            (client, server, auth_time)).fetchone()
        return r[0] if r else None

    def delete_credential_by_type(self, identity_id: int, ctype: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM credentials WHERE identity_id=? AND ctype=?", (identity_id, ctype))
        self._conn.commit()
        return cur.rowcount > 0

    def find_exact_ticket(self, identity_id: int, kind: str, server: str,
                          auth_time: Optional[str], end_time: Optional[str]) -> Optional[int]:
        """An already-stored ticket identical to this one (same instance)."""
        r = self._conn.execute(
            "SELECT id FROM tickets WHERE identity_id=? AND kind=? AND server=? "
            "AND auth_time IS ? AND end_time IS ? LIMIT 1",
            (identity_id, kind, server, auth_time, end_time)).fetchone()
        return r[0] if r else None

    def delete_tickets_like(self, identity_id: int, kind: str, server: str) -> int:
        """Remove tickets of the same kind+server for an identity (supersede)."""
        cur = self._conn.execute(
            "DELETE FROM tickets WHERE identity_id=? AND kind=? AND server=?",
            (identity_id, kind, server))
        self._conn.commit()
        return cur.rowcount
