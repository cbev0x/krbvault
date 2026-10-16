"""Request and renew Kerberos tickets from stored material.

This turns krbvault from passive storage into something that mints tickets:

  * ``request_tgt``  — a TGT from a stored password / NT hash / AES key
  * ``request_tgs``  — a service ticket (TGS) for an SPN, using a stored TGT
                       (no key needed) or by minting a TGT from a stored key
  * ``renew_tgt``    — renew a renewable TGT before it expires, using the ticket
                       itself (no key needed)
  * ``request_s4u``  — S4U2Self/S4U2Proxy: a service ticket for an SPN while
                       impersonating another user, driven by a service account's
                       stored TGT (constrained delegation)
  * ``request_pkinit`` — a TGT from a certificate (PFX/PKCS#12)

Each returns raw ccache bytes (a single-credential cache) for the caller to file
with the normal import path. TGT/TGS/renew are built on impacket; PKINIT uses
minikerberos; S4U reuses impacket's maintained getST so the intricate delegation
dance isn't re-implemented (and no key material touches the command line).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from binascii import unhexlify
from pathlib import Path
from typing import Optional

from . import kerberos

try:
    from impacket.krb5 import constants
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.types import Principal
    _HAVE_IMPACKET = True
except Exception:  # pragma: no cover
    _HAVE_IMPACKET = False

# PKINIT (PFX -> TGT) uses minikerberos, which is optional. Its import can also
# fail at runtime if oscrypto can't read the system OpenSSL version — we surface
# a clear hint for that below rather than crashing the whole module.
try:
    from minikerberos.client import KerbrosClient
    from minikerberos.common.creds import KerberosCredential
    from minikerberos.common.target import KerberosTarget
    _HAVE_MINIKERBEROS = True
    _MINIKERBEROS_ERR = None
except Exception as _exc:  # pragma: no cover
    _HAVE_MINIKERBEROS = False
    _MINIKERBEROS_ERR = _exc


class RequestError(Exception):
    pass


def _need() -> None:
    if not _HAVE_IMPACKET:
        raise RequestError("impacket is required for ticket requests (pip install impacket)")


def _principal(name: str, srv: bool = False) -> "Principal":
    ptype = (constants.PrincipalNameType.NT_SRV_INST.value if srv
             else constants.PrincipalNameType.NT_PRINCIPAL.value)
    return Principal(name, type=ptype)


def _get_tgt(username: str, domain: str, password: str, nthash: str,
             aeskey: str, kdc_host: Optional[str]):
    """getKerberosTGT wrapper → (as_rep_bytes, cipher, oldSessionKey, sessionKey)."""
    client = _principal(username)
    try:
        return getKerberosTGT(
            client, password or "", domain.upper(),
            b"", unhexlify(nthash) if nthash else b"",
            aeskey or "", kdcHost=kdc_host)
    except Exception as exc:
        raise RequestError(f"TGT request failed: {exc}") from exc


def _tgt_from_ccache(ccache_bytes: bytes):
    """Extract (KDC_REP, cipher, sessionKey) from a stored single-cred TGT cache."""
    cc = kerberos.load_ccache(ccache_bytes)
    if not cc.credentials:
        raise RequestError("stored ticket cache has no credentials")
    t = cc.credentials[0].toTGT()
    return t["KDC_REP"], t["cipher"], t["sessionKey"]


# --- public API --------------------------------------------------------------

def request_tgt(username: str, domain: str, *, password: str = "", nthash: str = "",
                aeskey: str = "", kdc_host: Optional[str] = None) -> bytes:
    _need()
    asrep, _cipher, old_key, session_key = _get_tgt(
        username, domain, password, nthash, aeskey, kdc_host)
    cc = CCache()
    cc.fromTGT(asrep, old_key, session_key)
    return cc.getData()


def request_tgs(spn: str, domain: str, *, tgt_ccache: Optional[bytes] = None,
                username: str = "", password: str = "", nthash: str = "",
                aeskey: str = "", kdc_host: Optional[str] = None) -> bytes:
    _need()
    if tgt_ccache is not None:
        kdc_rep, cipher, session_key = _tgt_from_ccache(tgt_ccache)
    else:
        kdc_rep, cipher, _old, session_key = _get_tgt(
            username, domain, password, nthash, aeskey, kdc_host)
    server = _principal(spn, srv=True)
    try:
        tgs, _cipher2, old_key2, session_key2 = getKerberosTGS(
            server, domain.upper(), kdc_host, kdc_rep, cipher, session_key)
    except Exception as exc:
        raise RequestError(f"service-ticket request failed: {exc}") from exc
    cc = CCache()
    cc.fromTGS(tgs, old_key2, session_key2)
    return cc.getData()


def renew_tgt(tgt_ccache: bytes, domain: str, *, kdc_host: Optional[str] = None) -> bytes:
    _need()
    kdc_rep, cipher, session_key = _tgt_from_ccache(tgt_ccache)
    server = _principal(f"krbtgt/{domain.upper()}", srv=True)
    try:
        tgs, _cipher2, old_key2, session_key2 = getKerberosTGS(
            server, domain.upper(), kdc_host, kdc_rep, cipher, session_key, renew=True)
    except Exception as exc:
        raise RequestError(f"renewal failed: {exc}") from exc
    cc = CCache()
    cc.fromTGS(tgs, old_key2, session_key2)
    return cc.getData()


def _find_getst() -> Optional[str]:
    """impacket's S4U implementation ships as the getST example script."""
    return shutil.which("getST.py") or shutil.which("impacket-getST")


def request_s4u(spn: str, domain: str, impersonate: str, *, tgt_ccache: bytes,
                service_user: str, kdc_host: Optional[str] = None) -> bytes:
    """S4U2Self + S4U2Proxy: a service ticket to ``spn`` *as* ``impersonate``,
    driven by the service account's own TGT.

    The full S4U dance (PA-FOR-USER, PA-PAC-OPTIONS, additional-tickets) lives in
    impacket's maintained ``getST`` rather than being re-implemented here. We feed
    it the service account's TGT through a throwaway ccache so no key material ever
    lands on the command line, then hand the resulting ticket back as ccache bytes
    for the normal import path.
    """
    getst = _find_getst()
    if getst is None:
        raise RequestError(
            "S4U needs impacket's getST (getST.py / impacket-getST) on PATH — "
            "it ships with impacket (pip install impacket)")
    if not tgt_ccache:
        raise RequestError("S4U needs the service account's TGT")

    work = Path(tempfile.mkdtemp(prefix="krbvault-s4u-"))
    try:
        tgt_path = work / "svc.ccache"
        tgt_path.write_bytes(tgt_ccache)
        try:
            tgt_path.chmod(0o600)
        except OSError:
            pass
        before = set(work.glob("*.ccache"))
        cmd = [getst, "-k", "-no-pass", "-spn", spn, "-impersonate", impersonate]
        if kdc_host:
            cmd += ["-dc-ip", kdc_host]
        cmd.append(f"{domain.upper()}/{service_user}")
        env = dict(os.environ, KRB5CCNAME=str(tgt_path))
        proc = subprocess.run(cmd, cwd=str(work), env=env,
                              capture_output=True, text=True)
        produced = [p for p in work.glob("*.ccache") if p not in before]
        if not produced:
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()
            msg = next((ln for ln in reversed(tail) if ln.strip()),
                       f"getST exited {proc.returncode}")
            raise RequestError(f"S4U failed: {msg.strip()}")
        out = max(produced, key=lambda p: p.stat().st_mtime)
        return out.read_bytes()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def request_pkinit(pfx_bytes: bytes, pfx_pass: str, username: str, domain: str,
                   *, kdc_host: Optional[str] = None) -> bytes:
    """PKINIT: get a TGT from a certificate (PFX/PKCS#12). Returns ccache bytes."""
    if not _HAVE_MINIKERBEROS:
        hint = ""
        if _MINIKERBEROS_ERR and "libcrypto" in str(_MINIKERBEROS_ERR).lower():
            hint = (" — oscrypto can't parse this OpenSSL version; upgrade it "
                    "(pip install -U oscrypto) or patch its version regex")
        raise RequestError(
            f"PKINIT needs minikerberos (pip install minikerberos){hint}: {_MINIKERBEROS_ERR}")
    if not kdc_host:
        raise RequestError("PKINIT needs the KDC address — pass --dc <ip>")
    try:
        cred = KerberosCredential.from_pfx_string(
            pfx_bytes, pfx_pass or "", username=username, domain=domain.upper())
        client = KerbrosClient(cred, KerberosTarget(kdc_host))
        client.get_TGT()
        return client.ccache.to_bytes()
    except RequestError:
        raise
    except Exception as exc:
        raise RequestError(f"PKINIT request failed: {exc}") from exc
