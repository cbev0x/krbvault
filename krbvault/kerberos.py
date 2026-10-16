"""Kerberos credential-cache handling: format detection, metadata extraction,
ccache <-> kirbi conversion, and ticket lifetime math.

This is read/convert plumbing over impacket's ccache parser — the same
information ``klist`` shows (client, SPN, flags, lifetime, etype). It does not
decrypt the ticket's encrypted part.
"""
from __future__ import annotations

import base64
import binascii
import datetime
import os
import tempfile
from typing import List, Optional, Tuple

try:
    from impacket.krb5 import constants
    from impacket.krb5.ccache import CCache
    _HAVE_IMPACKET = True
except Exception:  # pragma: no cover
    _HAVE_IMPACKET = False


class KerberosError(Exception):
    pass


def _need_impacket():
    if not _HAVE_IMPACKET:
        raise KerberosError("impacket is required for ticket handling "
                            "(pip install impacket)")


# --- format detection --------------------------------------------------------

def _looks_base64(data: bytes) -> bool:
    if not data or len(data) % 4 != 0:
        return False
    stripped = bytes(c for c in data if c not in b"\r\n")
    try:
        txt = stripped.decode("ascii")
    except UnicodeDecodeError:
        return False
    import string
    return all(c in (string.ascii_letters + string.digits + "+/=") for c in txt)


def detect_format(data: bytes) -> str:
    """Return 'ccache', 'kirbi', or 'unknown'. Base64 of a kirbi is decoded."""
    if not data:
        return "unknown"
    if _looks_base64(data):
        try:
            decoded = base64.b64decode(bytes(c for c in data if c not in b"\r\n"))
            if decoded and decoded[0] in (0x76, 0x05):
                return detect_format(decoded)
        except (binascii.Error, ValueError):
            pass
    if data[0] == 0x76:          # KRB-CRED, [APPLICATION 22]
        return "kirbi"
    if data[0] == 0x05:          # ccache magic (0x0504 for v4)
        return "ccache"
    return "unknown"


def normalize_to_bytes(data: bytes) -> bytes:
    """If data is base64 text of a ticket, decode it to raw bytes."""
    if _looks_base64(data):
        try:
            decoded = base64.b64decode(bytes(c for c in data if c not in b"\r\n"))
            if decoded and decoded[0] in (0x76, 0x05):
                return decoded
        except (binascii.Error, ValueError):
            pass
    return data


# --- loading / converting ----------------------------------------------------

def load_ccache(data: bytes) -> "CCache":
    """Parse raw ccache or kirbi bytes into an impacket CCache object."""
    _need_impacket()
    data = normalize_to_bytes(data)
    fmt = detect_format(data)
    if fmt == "kirbi":
        cc = CCache()
        cc.fromKRBCRED(data)
        return cc
    if fmt == "ccache":
        try:
            return CCache(data)
        except Exception:
            # fall back to the file loader
            fd, tmp = tempfile.mkstemp(suffix=".ccache")
            try:
                os.write(fd, data)
                os.close(fd)
                return CCache.loadFile(tmp)
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    raise KerberosError("unrecognized ticket format (expected ccache or kirbi)")


def to_ccache_bytes(cc: "CCache") -> bytes:
    return cc.getData()


def to_kirbi_bytes(cc: "CCache") -> bytes:
    return cc.toKRBCRED()


def split_single_credentials(cc: "CCache") -> List[bytes]:
    """Return one standalone single-credential ccache (bytes) per credential,
    so each ticket can be stored and selected independently."""
    _need_impacket()
    out = []
    for cred in cc.credentials:
        nc = CCache()
        nc.setDefaultHeader()
        # the ccache's default principal must be set for serialization;
        # use this credential's client principal.
        nc.principal = cred["client"]
        nc.credentials.append(cred)
        out.append(nc.getData())
    return out


# --- metadata extraction -----------------------------------------------------

def _iso(ts: int) -> Optional[str]:
    if not ts:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def _etype_name(n: int) -> str:
    if not _HAVE_IMPACKET:
        return str(n)
    try:
        return constants.EncryptionTypes(n).name
    except ValueError:
        return f"etype-{n}"


def _decode_flags(tktflags: int) -> List[str]:
    flags = []
    if not _HAVE_IMPACKET:
        return flags
    for fl in constants.TicketFlags:
        if tktflags & (1 << (31 - fl.value)):
            flags.append(fl.name)
    return flags


def _split_principal(pretty: str) -> Tuple[str, str]:
    """'user@REALM' -> ('user', 'REALM'); 'svc/host@REALM' stays as name/realm."""
    if "@" in pretty:
        name, realm = pretty.rsplit("@", 1)
        return name, realm
    return pretty, ""


def describe_credentials(cc: "CCache") -> List[dict]:
    """One metadata dict per credential in the ccache."""
    _need_impacket()
    results = []
    for cred in cc.credentials:
        server = cred.getServerPrincipal()
        server = server.decode() if isinstance(server, bytes) else str(server)
        client = cred["client"].prettyPrint()
        client = client.decode() if isinstance(client, bytes) else str(client)
        spn, server_realm = _split_principal(server)
        client_name, client_realm = _split_principal(client)
        kind = "TGT" if spn.lower().startswith("krbtgt/") else "TGS"
        t = cred["time"]
        etype = int(cred["key"]["keytype"])
        results.append({
            "kind": kind,
            "client": client_name,
            "client_realm": client_realm,
            "server": spn,
            "server_realm": server_realm,
            "flags": _decode_flags(int(cred["tktflags"])),
            "key_etype": etype,
            "etype_name": _etype_name(etype),
            "auth_time": _iso(t["authtime"]),
            "start_time": _iso(t["starttime"]),
            "end_time": _iso(t["endtime"]),
            "renew_till": _iso(t["renew_till"]),
        })
    return results


# --- lifetime ----------------------------------------------------------------

def ticket_status(end_iso: Optional[str], warn_seconds: int = 1800,
                  now: Optional[datetime.datetime] = None) -> Tuple[str, Optional[datetime.timedelta]]:
    """Return ('valid'|'expiring'|'expired'|'unknown', remaining-or-None)."""
    if not end_iso:
        return "unknown", None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    end = datetime.datetime.fromisoformat(end_iso)
    remaining = end - now
    if remaining.total_seconds() <= 0:
        return "expired", remaining
    if remaining.total_seconds() <= warn_seconds:
        return "expiring", remaining
    return "valid", remaining


def format_timedelta(td: Optional[datetime.timedelta]) -> str:
    if td is None:
        return "-"
    secs = int(td.total_seconds())
    sign = "-" if secs < 0 else ""
    secs = abs(secs)
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    if d:
        return f"{sign}{d}d{h}h"
    if h:
        return f"{sign}{h}h{m}m"
    return f"{sign}{m}m"
