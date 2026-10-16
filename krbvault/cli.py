"""krbvault command-line interface."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional

from . import __version__, activate, agent, config, emit, kerberos, request
from .crypto import BadPassphrase
from .models import CredType, IdentityType, Ticket
from .store import LockedError, Store, StoreError

# --- output: colour + layout ------------------------------------------------
# Spare output in the klist / kubectl / impacket idiom. Colour stays off the
# default foreground except two channels — identity/ticket TYPE, and ticket
# LIFETIME (green/yellow/red) — gated on a real TTY (honouring NO_COLOR and
# --color). When stdout is a pipe, `ls` emits tab-separated rows (porcelain).

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "bright_blue": "\033[94m", "bright_magenta": "\033[95m",
}
_USE_COLOR = False
_PLAIN = False  # stdout is not a TTY -> machine-readable (tab-separated) layout


def _configure_output(color_mode: str = "auto", no_color: bool = False) -> None:
    global _USE_COLOR, _PLAIN
    _PLAIN = not sys.stdout.isatty()
    if no_color or color_mode == "never":
        _USE_COLOR = False
    elif color_mode == "always":
        _USE_COLOR = True
    else:  # auto: colour only on a TTY, and never when NO_COLOR is present
        _USE_COLOR = (not _PLAIN) and ("NO_COLOR" not in os.environ)


def _c(text: str, *styles: str) -> str:
    """Wrap text in ANSI styles when colour is on, else return it unchanged."""
    if not _USE_COLOR or not styles:
        return text
    pre = "".join(_ANSI.get(s, "") for s in styles)
    return f"{pre}{text}{_ANSI['reset']}" if pre else text


def _echo(msg: str = "") -> None:
    print(msg)


# status tags, in the impacket / nxc / certipy idiom: [+] ok, [*] info,
# [!] warning, [-] error. The glyph carries the signal; colour only reinforces.
def _tag(sym: str, msg: str, color: Optional[str] = None, stream=None) -> None:
    label = _c(f"[{sym}]", color) if color else f"[{sym}]"
    print(f"{label} {msg}", file=stream or sys.stdout)


def _ok(msg: str) -> None:
    _tag("+", msg, "green")


def _info(msg: str) -> None:
    _tag("*", msg, "blue")


def _warn(msg: str) -> None:
    _tag("!", msg, "yellow")


def _err(msg: str) -> None:
    _tag("-", msg, "red", sys.stderr)


_ITYPE_COLOR = {
    "user": ("cyan",), "computer": ("magenta",), "service": ("bright_blue",),
    "krbtgt": ("bold", "bright_magenta"), "unknown": (),
}


def _itype(itype: str) -> str:
    return _c(itype, *_ITYPE_COLOR.get(itype, ()))


_LIFE_COLOR = {"valid": "green", "expiring": "yellow", "expired": "red", "unknown": None}


def _life(status: str, remaining, bracket: bool = False) -> str:
    """Coloured lifetime token. bracket=True gives the `[valid 6h4m]` detail form."""
    if status in ("valid", "expiring"):
        body = (f"{status} {kerberos.format_timedelta(remaining)}" if bracket
                else kerberos.format_timedelta(remaining))
    elif status == "expired":
        body = "expired"
    else:
        body = "-"
    text = f"[{body}]" if bracket else body
    color = _LIFE_COLOR.get(status)
    return _c(text, color) if color else text


def _expiry_short(end_iso):
    """(text, color) coarse single-unit expiry for the ls EXPIRES column."""
    status, rem = kerberos.ticket_status(end_iso)
    color = _LIFE_COLOR.get(status)
    if status == "unknown":
        return "-", None
    if status == "expired":
        return "expired", color
    secs = max(1, int(rem.total_seconds()))
    d, h, m = secs // 86400, (secs % 86400) // 3600, (secs % 3600) // 60
    if d >= 365:
        txt = f"{d // 365}y"
    elif d:
        txt = f"{d}d"
    elif h:
        txt = f"{h}h"
    else:
        txt = f"{m or 1}m"
    return txt, color


_ETYPE_SHORT = {18: "aes256", 17: "aes128", 23: "rc4", 24: "rc4-exp",
                16: "des3", 3: "des-md5", 1: "des-crc"}


def _etype_short(num, name=None) -> str:
    if num in _ETYPE_SHORT:
        return _ETYPE_SHORT[num]
    if name:  # e.g. aes256_cts_hmac_sha1_96 -> aes256
        return name.split("_", 1)[0]
    return str(num) if num is not None else "?"


# klist-style single-letter flags, printed in this order.
_FLAG_LETTERS = [
    ("forwardable", "F"), ("forwarded", "f"), ("proxiable", "P"), ("proxy", "p"),
    ("may_postdate", "D"), ("postdated", "d"), ("invalid", "i"), ("renewable", "R"),
    ("initial", "I"), ("pre_authent", "A"), ("hw_authent", "H"),
    ("transited_policy_checked", "T"), ("ok_as_delegate", "O"),
    ("anonymous", "a"), ("name_canonicalize", "C"), ("enc_pa_rep", "E"),
]


def _flag_letters(flags) -> str:
    s = {f.lower() for f in (flags or [])}
    return "".join(ltr for name, ltr in _FLAG_LETTERS if name in s) or "-"


# --- passphrase / unlock helpers --------------------------------------------

def _prompt_passphrase(confirm: bool = False) -> str:
    env = os.environ.get("KRBVAULT_PASSPHRASE")
    if env is not None:
        return env
    pw = getpass.getpass("Passphrase: ")
    if confirm:
        again = getpass.getpass("Confirm:    ")
        if pw != again:
            raise SystemExit("error: passphrases did not match")
    return pw


def _open_store(args) -> Store:
    path = config.resolve_store(getattr(args, "engagement", None),
                                getattr(args, "store", None))
    return Store.open(path)


def _unlock(store: Store) -> Store:
    """Unlock via a running agent if present, else prompt for the passphrase."""
    if not store.locked:
        return store
    dek = agent.query(store.path)
    if dek is not None:
        try:
            store.unlock_with_dek(dek)
            return store
        except BadPassphrase:
            pass  # stale agent for a different vault; fall through to prompt
    store.unlock(_prompt_passphrase())
    return store


# --- selector resolution -----------------------------------------------------

def _is_ticket_selector(sel: str) -> bool:
    return sel.startswith("#") or sel.isdigit()


def _ticket_id(sel: str) -> int:
    return int(sel[1:] if sel.startswith("#") else sel)


_AES_ETYPES = (17, 18)  # aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96


def _pick_ticket(store: Store, identity_id: int) -> Optional[Ticket]:
    tickets = store.list_tickets(identity_id)
    if not tickets:
        return None
    # Freshest first, so equally-ranked tickets break toward the one most recently
    # obtained — a just-minted TGT beats a stale or forged long-life one.
    tickets = sorted(tickets, key=lambda t: t.created_at or "", reverse=True)
    rank = {"valid": 0, "expiring": 1, "unknown": 2, "expired": 3}

    def score(t: Ticket):
        status, _ = kerberos.ticket_status(t.end_time)
        aes = 0 if t.key_etype in _AES_ETYPES else 1
        return (rank.get(status, 4), 0 if t.kind == "TGT" else 1, aes)

    return sorted(tickets, key=score)[0]


# --- commands ----------------------------------------------------------------

def cmd_init(args) -> int:
    path = config.resolve_store(args.engagement, args.store)
    if path.exists():
        _err(f"vault already exists: {path}")
        return 1
    pw = _prompt_passphrase(confirm=True)
    store = Store.create(path, pw, args.engagement or "default")
    store.close()
    _ok(f"Created vault: {path}")
    _echo(f"Engagement:    {args.engagement or 'default'}")
    _echo("")
    _info("Add this to your shell rc (once) so tools read the active ticket:")
    _echo(f"    {config.shell_env_line()}")
    return 0


def cmd_status(args) -> int:
    path = config.resolve_store(args.engagement, args.store)
    as_json = getattr(args, "json", False)
    if not path.exists():
        if as_json:
            print(json.dumps({"vault": str(path), "exists": False}, indent=2))
        else:
            _echo(f"No vault at {path}")
        return 0
    store = Store.open(path)
    unlocked = agent.is_running(store.path)
    idents = store.list_identities()
    n_cred = sum(store.counts(i.id)[0] for i in idents)
    n_tkt = sum(store.counts(i.id)[1] for i in idents)
    if as_json:
        active_id = _active_ticket_id(store)
        active = None
        if active_id:
            at = store.get_ticket(active_id)
            ai = store.get_identity_by_id(at.identity_id)
            st, rem = kerberos.ticket_status(at.end_time)
            active = {"id": at.id, "identity": ai.upn, "kind": at.kind,
                      "status": st, "remaining": kerberos.format_timedelta(rem)}
        krb_path = str(config.active_ccache_path())
        print(json.dumps({
            "vault": str(path), "exists": True, "engagement": store.engagement,
            "unlocked": unlocked, "identities": len(idents), "realms": store.realms(),
            "credentials": n_cred, "tickets": n_tkt, "active": active,
            "krb5ccname_path": krb_path,
            "krb5ccname_set": os.environ.get("KRB5CCNAME") == krb_path,
        }, indent=2))
        store.close()
        return 0
    agent_state = (_c("unlocked (agent running)", "green") if unlocked
                   else _c("locked", "dim"))
    _echo(f"Vault:       {path}")
    _echo(f"Engagement:  {store.engagement}")
    _echo(f"Agent:       {agent_state}")
    _echo(f"Identities:  {len(idents)} in {len(store.realms())} realm(s)")
    _echo(f"Credentials: {n_cred}    Tickets: {n_tkt}")
    active_id = _active_ticket_id(store)
    if active_id:
        at = store.get_ticket(active_id)
        ai = store.get_identity_by_id(at.identity_id)
        st, rem = kerberos.ticket_status(at.end_time)
        _echo(f"Active:      #{at.id} {ai.upn} {at.kind} {_life(st, rem)}")
    else:
        _echo("Active:      (none from this vault)")
    active = str(config.active_ccache_path())
    if os.environ.get("KRB5CCNAME") == active:
        _echo(f"KRB5CCNAME:  {active} (set in this shell)")
    else:
        hint = _c('— NOT set in this shell; run: eval "$(krbvault env)"', "yellow")
        _echo(f"KRB5CCNAME:  {active} {hint}")
    store.close()
    return 0


def cmd_unlock(args) -> int:
    store = _open_store(args)
    dek = store.derive_dek(_prompt_passphrase())
    agent.start(store.path, dek, ttl=args.ttl)
    _ok(f"Unlocked. Agent holds the key for {args.ttl}s ({args.ttl // 3600}h).")
    store.close()
    return 0


def cmd_lock(args) -> int:
    store = _open_store(args)
    agent.stop(store.path)
    _info("Locked (agent stopped).")
    store.close()
    return 0


def _file_tickets(store, ccache_bytes, source, identity_override=None, replace=False):
    """Parse ccache bytes, split per credential, and store each as a ticket.
    Skips exact duplicates; with replace=True, supersedes same kind+server.
    Returns a list of (ticket_id, identity, metadata-dict, state) where state is
    'new' or 'dup'."""
    cc = kerberos.load_ccache(ccache_bytes)
    metas = kerberos.describe_credentials(cc)
    blobs = kerberos.split_single_credentials(cc)
    filed = []
    for meta, blob in zip(metas, blobs):
        if identity_override:
            principal, realm = identity_override.rsplit("@", 1)
        else:
            principal, realm = meta["client"], meta["client_realm"]
        itype = (IdentityType.COMPUTER.value if principal.endswith("$")
                 else IdentityType.USER.value)
        ident = store.add_identity(principal, realm, itype=itype)
        if replace:
            store.delete_tickets_like(ident.id, meta["kind"], meta["server"])
        dup = store.find_exact_ticket(ident.id, meta["kind"], meta["server"],
                                      meta["auth_time"], meta["end_time"])
        if dup is not None:
            filed.append((dup, ident, meta, "dup"))
            continue
        t = Ticket(id=None, identity_id=ident.id, kind=meta["kind"],
                   client=meta["client"], client_realm=meta["client_realm"],
                   server=meta["server"], server_realm=meta["server_realm"],
                   flags=meta["flags"], key_etype=meta["key_etype"],
                   etype_name=meta["etype_name"], auth_time=meta["auth_time"],
                   start_time=meta["start_time"], end_time=meta["end_time"],
                   renew_till=meta["renew_till"], blob=blob, source=source)
        filed.append((store.add_ticket(ident.id, t), ident, meta, "new"))
    return filed


def _print_filed(filed) -> None:
    for tid, ident, meta, state in filed:
        status, remaining = kerberos.ticket_status(meta["end_time"])
        etype = _etype_short(meta["key_etype"], meta["etype_name"])
        detail = f"#{tid} {meta['kind']:<3} {ident.upn}  ({etype}, {_life(status, remaining)})"
        if state == "dup":
            _tag("*", f"{detail}  already stored", "dim")
        else:
            _ok(detail)


def _best_tgt(store, identity_id):
    """Pick a usable TGT for an identity: prefer a live one, AES over RC4/DES, and
    the most recently obtained within that — so a freshly minted AES TGT wins over
    a stale or forged long-life ticket that merely has a farther expiry (driving a
    TGS/renew off an RC4 golden ticket gets KDC_ERR_ETYPE_NOSUPP on modern DCs)."""
    tickets = sorted(store.list_tickets(identity_id),
                     key=lambda t: t.created_at or "", reverse=True)  # freshest first
    tgts = [t for t in tickets if t.kind == "TGT"]
    live = [t for t in tgts
            if kerberos.ticket_status(t.end_time)[0] in ("valid", "expiring")]
    pool = live or tgts
    if not pool:
        return None
    # stable sort keeps freshest-first; push AES ahead of RC4/DES
    pool.sort(key=lambda t: 0 if t.key_etype in _AES_ETYPES else 1)
    return pool[0]


def _active_ticket_id(store):
    """Which stored ticket (if any) the active KRB5CCNAME cache corresponds to.
    Matches on plaintext metadata, so it works without unlocking."""
    path = config.active_ccache_path()
    if not path.exists():
        return None
    try:
        metas = kerberos.describe_credentials(kerberos.load_ccache(path.read_bytes()))
    except Exception:
        return None
    if not metas:
        return None
    m = metas[0]
    return store.find_ticket_by_meta(m["client"], m["server"], m["auth_time"])


def _ticket_dict(t, active_id=None) -> dict:
    status, remaining = kerberos.ticket_status(t.end_time)
    return {
        "id": t.id, "kind": t.kind, "client": t.client, "client_realm": t.client_realm,
        "server": t.server, "server_realm": t.server_realm,
        "etype": t.etype_name, "etype_num": t.key_etype, "flags": t.flags,
        "auth_time": t.auth_time, "start_time": t.start_time, "end_time": t.end_time,
        "renew_till": t.renew_till, "status": status,
        "remaining": kerberos.format_timedelta(remaining),
        "active": t.id == active_id, "source": t.source,
    }


def _identity_dict(store, ident, active_id=None) -> dict:
    return {
        "principal": ident.principal, "realm": ident.realm, "upn": ident.upn,
        "type": ident.itype, "sid": ident.sid, "notes": ident.notes,
        "credentials": [c.ctype for c in store.list_credentials(ident.id)],
        "tickets": [_ticket_dict(t, active_id) for t in store.list_tickets(ident.id)],
    }


def cmd_import(args) -> int:
    src = Path(args.file)
    if not src.is_file():
        _err(f"no such file: {args.file}")
        return 1
    data = src.read_bytes()
    if kerberos.detect_format(data) == "unknown":
        _err("could not detect ticket format (expected ccache or kirbi)")
        return 1
    store = _unlock(_open_store(args))
    filed = _file_tickets(store, data, args.source or f"import:{Path(args.file).name}",
                          identity_override=args.identity, replace=args.replace)
    _print_filed(filed)
    store.close()
    n_new = sum(1 for f in filed if f[3] == "new")
    extra = f", {len(filed) - n_new} already present" if n_new != len(filed) else ""
    (_ok if n_new else _info)(f"Imported {n_new} ticket(s){extra}.")
    return 0


def cmd_request(args) -> int:
    if "@" not in args.identity:
        _err("identity must be principal@REALM")
        return 1
    principal, realm = args.identity.rsplit("@", 1)
    dc = args.dc or config.get_dc(realm)
    store = _unlock(_open_store(args))
    ident = store.get_identity(args.identity)
    cred_ids = {c.ctype: c.id for c in store.list_credentials(ident.id)} if ident else {}

    # PKINIT: a TGT from a stored certificate (PFX)
    if args.pfx:
        if args.spn:
            _err("--pfx requests a TGT; run a separate 'request --spn' for a service ticket")
            return 1
        if "pfx" not in cred_ids:
            _err(f"{args.identity} has no stored PFX "
                 f"(add one with 'krbvault add {args.identity} --pfx <file>')")
            return 1
        pfx_bytes = store.reveal_credential(cred_ids["pfx"])[1]
        try:
            data = request.request_pkinit(pfx_bytes, args.pfx_pass or "",
                                          principal, realm, kdc_host=dc)
        except request.RequestError as exc:
            _err(str(exc))
            return 1
        _print_filed(_file_tickets(store, data, "pkinit", replace=args.replace))
        store.close()
        return 0

    # choose a key to mint from: strongest first, or an explicit --ctype
    # Prefer material that yields AES (aes keys, or a password impacket derives
    # AES from) over an NT hash (RC4 only) — modern DCs reject RC4, and an RC4
    # request is a downgrade signal. Override with --ctype.
    order = [args.ctype] if args.ctype else ["aes256", "aes128", "password", "nt", "rc4"]
    chosen = next((ct for ct in order if ct in cred_ids), None)

    # for a service ticket we can use a stored TGT (no key needed)
    tgt_ccache = None
    if args.spn and ident:
        tgt = _best_tgt(store, ident.id)
        if tgt:
            tgt_ccache = store.reveal_ticket(tgt.id)

    if not args.spn and chosen is None:
        _err(f"{args.identity} has no stored key to request a TGT "
             f"(add one with 'krbvault add')")
        return 1
    if args.spn and tgt_ccache is None and chosen is None:
        _err(f"{args.identity} has no stored TGT or key for a service ticket")
        return 1

    kw = {"password": "", "nthash": "", "aeskey": "", "kdc_host": dc}
    if chosen:
        value = store.reveal_credential(cred_ids[chosen])[1].decode("utf-8", "replace")
        if chosen in ("aes256", "aes128", "aeskey"):
            kw["aeskey"] = value
        elif chosen in ("nt", "rc4"):
            kw["nthash"] = value
        elif chosen == "password":
            kw["password"] = value

    if chosen in ("nt", "rc4") and tgt_ccache is None:
        _info("minting with RC4 (NT hash); modern DCs often reject it — "
              "store a password or AES key to request AES instead.")

    # S4U (constrained delegation): a service ticket for --spn while impersonating
    # another user, driven by the service account's TGT (stored, or minted here).
    if args.impersonate:
        if not args.spn:
            _err("--impersonate requires --spn (S4U issues a service ticket)")
            return 1
        svc_tgt = tgt_ccache
        if svc_tgt is None:
            try:
                svc_tgt = request.request_tgt(principal, realm, **kw)
            except request.RequestError as exc:
                _err(str(exc))
                return 1
        try:
            data = request.request_s4u(args.spn, realm, args.impersonate,
                                       tgt_ccache=svc_tgt, service_user=principal,
                                       kdc_host=dc)
        except request.RequestError as exc:
            _err(str(exc))
            return 1
        _print_filed(_file_tickets(store, data, f"s4u:{args.impersonate}@{args.spn}",
                                   replace=args.replace))
        store.close()
        return 0

    try:
        if args.spn:
            data = request.request_tgs(args.spn, realm, tgt_ccache=tgt_ccache,
                                       username=principal, **kw)
            src = f"request:{args.spn}"
        else:
            data = request.request_tgt(principal, realm, **kw)
            src = "request"
    except request.RequestError as exc:
        _err(str(exc))
        return 1

    _print_filed(_file_tickets(store, data, src, replace=args.replace))
    store.close()
    return 0


def cmd_renew(args) -> int:
    store = _unlock(_open_store(args))
    sel = args.selector
    if _is_ticket_selector(sel):
        t = store.get_ticket(_ticket_id(sel))
        if not t:
            _err(f"no ticket {sel}")
            return 1
        ident = store.get_identity_by_id(t.identity_id)
    else:
        ident = store.get_identity(sel)
        if not ident:
            _err(f"no identity {sel}")
            return 1
        t = _best_tgt(store, ident.id)
        if not t:
            _err(f"{ident.upn} has no TGT to renew")
            return 1
    if t.kind != "TGT":
        _err(f"#{t.id} is a {t.kind}, not a renewable TGT")
        return 1
    if "renewable" not in t.flags:
        _err(f"#{t.id} is not renewable")
        return 1

    ccache = store.reveal_ticket(t.id)
    realm = t.client_realm or ident.realm
    try:
        data = request.renew_tgt(ccache, realm, kdc_host=args.dc or config.get_dc(realm))
    except request.RequestError as exc:
        _err(str(exc))
        return 1
    _print_filed(_file_tickets(store, data, "renew", replace=args.replace))
    store.close()
    return 0


_CTYPE_FLAGS = {
    "password": CredType.PASSWORD, "nt": CredType.NT, "aes256": CredType.AES256,
    "aes128": CredType.AES128, "rc4": CredType.RC4, "des": CredType.DES,
    "aeskey": CredType.AESKEY,
}


def cmd_add(args) -> int:
    if "@" not in args.identity:
        _err("identity must be principal@REALM")
        return 1
    principal, realm = args.identity.rsplit("@", 1)
    itype = (IdentityType.COMPUTER.value if principal.endswith("$")
             else IdentityType.USER.value)

    store = _unlock(_open_store(args))
    ident = store.add_identity(principal, realm, itype=itype)

    def _put(ctype: str, value: bytes) -> None:
        replaced = store.has_credential(ident.id, ctype)
        store.add_credential(ident.id, ctype, value, source=args.source)
        if replaced:
            _info(f"{ctype} for {ident.upn} (replaced)")
        else:
            _ok(f"{ctype} for {ident.upn}")

    n = 0
    for flag, ctype in _CTYPE_FLAGS.items():
        val = getattr(args, flag)
        if val:
            _put(ctype.value, val.encode())
            n += 1
    if args.pfx:
        pfx_path = Path(args.pfx)
        if not pfx_path.is_file():
            _err(f"no such PFX file: {args.pfx}")
            store.close()
            return 1
        _put(CredType.PFX.value, pfx_path.read_bytes())
        n += 1
    store.close()
    if n == 0:
        _err("no credential provided (use --password/--nt/--aes256/--pfx/...)")
        return 1
    return 0


_LS_HEADERS = ("IDENTITY", "TYPE", "CREDS", "TICKET", "EXPIRES")


def _ls_row(store, ident, active_id):
    """One ls row as a list of (plain, coloured) cells."""
    creds = ",".join(sorted({c.ctype for c in store.list_credentials(ident.id)})) or "-"
    tix = store.list_tickets(ident.id)
    best = _pick_ticket(store, ident.id)
    if best:
        extra = len(tix) - 1
        tcol = f"#{best.id} {best.kind}" + (f" +{extra}" if extra > 0 else "")
        active = best.id == active_id
        if active:
            tcol += " *"
        exp_txt, exp_color = _expiry_short(best.end_time)
        tcol_c = _c(tcol, "bold") if active else tcol
        exp_c = _c(exp_txt, exp_color) if exp_color else exp_txt
    else:
        tcol = tcol_c = exp_txt = exp_c = "-"
    return [
        (ident.principal, ident.principal),
        (ident.itype, _itype(ident.itype)),
        (creds, creds),
        (tcol, tcol_c),
        (exp_txt, exp_c),
    ]


def cmd_ls(args) -> int:
    store = _open_store(args)
    idents = store.list_identities(args.domain)
    if getattr(args, "json", False):
        active_id = _active_ticket_id(store)
        print(json.dumps([_identity_dict(store, i, active_id) for i in idents], indent=2))
        store.close()
        return 0
    active_id = _active_ticket_id(store)
    rows = [(i, _ls_row(store, i, active_id)) for i in idents]

    # Piped (and colour not forced): tab-separated with a REALM column, no colour —
    # awk/cut/jq-free scripting. `--color always` keeps the grouped terminal layout.
    if _PLAIN and not _USE_COLOR:
        print("\t".join(("REALM",) + _LS_HEADERS))
        for ident, row in rows:
            print("\t".join([ident.realm] + [plain for plain, _col in row]))
        store.close()
        return 0

    if not idents:
        _echo("(empty)")
        store.close()
        return 0

    # TTY: borderless columns grouped by realm, widths shared across all groups.
    widths = [len(h) for h in _LS_HEADERS]
    for _ident, row in rows:
        for i, (plain, _col) in enumerate(row):
            widths[i] = max(widths[i], len(plain))
    gap = "   "
    by_realm = {}
    for ident, row in rows:
        by_realm.setdefault(ident.realm, []).append(row)
    for n, (realm, realm_rows) in enumerate(by_realm.items()):
        if n:
            print()
        print(_c(realm, "bold"))
        header = gap.join(h.ljust(widths[i]) if i < len(_LS_HEADERS) - 1 else h
                          for i, h in enumerate(_LS_HEADERS))
        rule = "─" * (sum(widths) + len(gap) * (len(_LS_HEADERS) - 1))
        print(_c(header, "dim"))
        print(_c(rule, "dim"))
        for row in realm_rows:
            cells = [(colored + " " * (widths[i] - len(plain))) if i < len(row) - 1 else colored
                     for i, (plain, colored) in enumerate(row)]
            print(gap.join(cells))
    store.close()
    return 0


def cmd_describe(args) -> int:
    store = _open_store(args)
    sel = args.selector
    if _is_ticket_selector(sel):
        t = store.get_ticket(_ticket_id(sel))
        if not t:
            _err(f"no ticket {sel}")
            return 1
        if getattr(args, "json", False):
            print(json.dumps(_ticket_dict(t, _active_ticket_id(store)), indent=2))
            store.close()
            return 0
        status, remaining = kerberos.ticket_status(t.end_time)
        _echo(f"Ticket #{t.id}  {t.kind}")
        _echo(f"  client:     {t.client}@{t.client_realm}")
        _echo(f"  server:     {t.server}@{t.server_realm}")
        _echo(f"  etype:      {_etype_short(t.key_etype, t.etype_name)} ({t.key_etype})")
        _echo(f"  flags:      {_flag_letters(t.flags)}  ({', '.join(t.flags) or '-'})")
        _echo(f"  starts:     {t.start_time}")
        _echo(f"  expires:    {t.end_time}  {_life(status, remaining, bracket=True)}")
        _echo(f"  renew till: {t.renew_till or '-'}")
        _echo(f"  source:     {t.source or '-'}")
        _echo("  PAC:        not decoded — group/SID data is in the ticket's")
        _echo("              encrypted part and needs the service/krbtgt key,")
        _echo("              which a captured ticket doesn't carry.")
    else:
        ident = store.get_identity(sel)
        if not ident:
            _err(f"no identity {sel}")
            return 1
        if getattr(args, "json", False):
            print(json.dumps(_identity_dict(store, ident, _active_ticket_id(store)), indent=2))
            store.close()
            return 0
        _echo(f"{ident.upn}  {_itype(ident.itype)}")
        if ident.sid:
            _echo(f"  sid:   {ident.sid}")
        if ident.notes:
            _echo(f"  notes: {ident.notes}")
        creds = store.list_credentials(ident.id)
        _echo(f"  credentials: {', '.join(c.ctype for c in creds) or '-'}")
        tickets = store.list_tickets(ident.id)
        active_id = _active_ticket_id(store)
        _echo("  tickets:")
        if not tickets:
            _echo("    -")
        else:
            _echo("    " + _c(f"{'ID':<4}{'KIND':5}{'FLAGS':8}{'SERVICE':30}EXPIRES", "dim"))
            for t in tickets:
                status, remaining = kerberos.ticket_status(t.end_time)
                marker = _c(" *", "bold") if t.id == active_id else ""
                _echo(f"    {('#' + str(t.id)):<4}{t.kind:5}{_flag_letters(t.flags):8}"
                      f"{t.server:30}{_life(status, remaining)}{marker}")
    store.close()
    return 0


def cmd_use(args) -> int:
    store = _unlock(_open_store(args))
    sel = args.selector
    if _is_ticket_selector(sel):
        t = store.get_ticket(_ticket_id(sel))
        if not t:
            _err(f"no ticket {sel}")
            return 1
        ident = store.get_identity_by_id(t.identity_id)
    else:
        ident = store.get_identity(sel)
        if not ident:
            _err(f"no identity {sel}")
            return 1
        t = _pick_ticket(store, ident.id)
        if not t:
            _err(f"{ident.upn} has no stored ticket")
            return 1

    blob = store.reveal_ticket(t.id)
    status, remaining = kerberos.ticket_status(t.end_time)
    if status == "expired":
        _warn(f"ticket #{t.id} is expired ({t.end_time})")

    if args.shell:
        _info(f"Spawning subshell as {ident.upn} (ticket #{t.id}); exit to return.")
        rc = activate.run_subshell(blob, store.path, ident.upn)
        store.close()
        return rc
    elif args.export:
        path = activate.set_export(blob, store.path, ident.upn)
        print(f'export KRB5CCNAME="{path}"')
    else:
        activate.set_active(blob)
        _ok(f"Active: {ident.upn}  (ticket #{t.id}, {t.kind}, {_life(status, remaining)})")
        _warn_if_krb5ccname_unwired()

    if args.for_tool:
        _emit_for(store, ident, args.for_tool, args.target,
                  ccache_path=str(config.active_ccache_path()))
    store.close()
    return 0


def _warn_if_krb5ccname_unwired() -> None:
    """A child process can't set the parent shell's env, so warn (loudly) when
    KRB5CCNAME isn't pointed at the active cache — tools won't see the ticket."""
    active = str(config.active_ccache_path())
    current = os.environ.get("KRB5CCNAME")
    if current == active:
        return
    if not current:
        _warn("KRB5CCNAME is not set in this shell — tools won't see this ticket yet.")
    else:
        _warn(f"KRB5CCNAME points at {current}, not krbvault's active cache — "
              "tools won't see this ticket.")
    _echo(f'    export KRB5CCNAME="{active}"')
    _echo('    (add to ~/.zshrc or ~/.bashrc; or this session: eval "$(krbvault env)")')


def _emit_for(store: Store, ident, tool: str, target: str,
              ccache_path: Optional[str] = None) -> None:
    kwargs = dict(user=ident.principal, domain=ident.realm.lower(),
                  target=target or "<target>", ccache_path=ccache_path)
    for c in store.list_credentials(ident.id):
        ctype, value = store.reveal_credential(c.id)
        val = value.decode("utf-8", "replace")
        if ctype in ("nt", "rc4"):
            kwargs["nt"] = val
        elif ctype == "aes256":
            kwargs["aes256"] = val
        elif ctype == "aes128":
            kwargs["aes128"] = val
        elif ctype == "password":
            kwargs["password"] = val
    print()
    for line in emit.emit(tool, **kwargs):
        print(line)  # raw: emitted commands must stay copy-pasteable (no wrapping)


def cmd_emit(args) -> int:
    store = _unlock(_open_store(args))
    ident = store.get_identity(args.identity)
    if not ident:
        _err(f"no identity {args.identity}")
        return 1
    ccpath = None
    best = _pick_ticket(store, ident.id)
    if best:
        # materialize to the per-identity export path so the emitted line is runnable
        blob = store.reveal_ticket(best.id)
        ccpath = str(activate.set_export(blob, store.path, ident.upn))
    _emit_for(store, ident, args.for_tool, args.target, ccache_path=ccpath)
    store.close()
    return 0


def cmd_reveal(args) -> int:
    store = _unlock(_open_store(args))
    ident = store.get_identity(args.identity)
    if not ident:
        _err(f"no identity {args.identity}")
        return 1
    for c in store.list_credentials(ident.id):
        if args.ctype and c.ctype != args.ctype:
            continue
        ctype, value = store.reveal_credential(c.id)
        if ctype == "pfx":
            out = Path(f"{ident.principal}.pfx")
            out.write_bytes(value)
            _echo(f"{ctype}: written to {out} ({len(value)} bytes)")
        else:
            _echo(f"{ctype}: {value.decode('utf-8', 'replace')}")
    store.close()
    return 0


def cmd_rm(args) -> int:
    store = _open_store(args)
    sel = args.selector
    if _is_ticket_selector(sel):
        if args.ctype:
            _err("--ctype removes a credential from an identity, not a #ticket")
            return 1
        store.delete_ticket(_ticket_id(sel))
        _info(f"Deleted ticket {sel}")
    else:
        ident = store.get_identity(sel)
        if not ident:
            _err(f"no identity {sel}")
            return 1
        if args.ctype:
            if store.delete_credential_by_type(ident.id, args.ctype):
                _info(f"Deleted {args.ctype} credential from {ident.upn}")
            else:
                _err(f"{ident.upn} has no {args.ctype} credential")
                return 1
        else:
            store.delete_identity(ident.id)
            _info(f"Deleted {ident.upn} (and its credentials/tickets)")
    store.close()
    return 0


def cmd_export(args) -> int:
    store = _unlock(_open_store(args))
    sel = args.selector
    if _is_ticket_selector(sel):
        t = store.get_ticket(_ticket_id(sel))
        if not t:
            _err(f"no ticket {sel}")
            return 1
    else:
        ident = store.get_identity(sel)
        if not ident:
            _err(f"no identity {sel}")
            return 1
        tickets = store.list_tickets(ident.id)
        t = _best_tgt(store, ident.id) or (tickets[0] if tickets else None)
        if not t:
            _err(f"{ident.upn} has no ticket to export")
            return 1

    blob = store.reveal_ticket(t.id)
    if args.kirbi:
        data = kerberos.to_kirbi_bytes(kerberos.load_ccache(blob))
        ext = "kirbi"
    else:
        data = blob
        ext = "ccache"
    out = Path(args.output) if args.output else Path(f"{t.client}_{t.kind}_{t.id}.{ext}")
    out.write_bytes(data)
    try:
        out.chmod(0o600)
    except OSError:
        pass
    _ok(f"Exported #{t.id} {t.kind} {t.client}@{t.client_realm} -> {out} ({ext})")
    store.close()
    return 0


def cmd_purge(args) -> int:
    store = _open_store(args)
    if args.selector:
        ident = store.get_identity(args.selector)
        if not ident:
            _err(f"no identity {args.selector}")
            return 1
        tickets = store.list_tickets(ident.id)
    else:
        tickets = store.list_tickets()
    removed = 0
    for t in tickets:
        if kerberos.ticket_status(t.end_time)[0] == "expired":
            store.delete_ticket(t.id)
            removed += 1
    _info(f"Purged {removed} expired ticket(s).")
    store.close()
    return 0


def cmd_config(args) -> int:
    if getattr(args, "action", None) == "dc":
        if args.unset:
            ok = config.unset_dc(args.realm)
            _info(f"Removed DC for {args.realm.upper()}" if ok
                  else f"No DC was set for {args.realm.upper()}")
        elif args.ip:
            config.set_dc(args.realm, args.ip)
            _ok(f"Set {args.realm.upper()} KDC = {args.ip}")
        else:
            _err("provide an IP (krbvault config dc <REALM> <IP>) or --unset")
            return 1
        return 0
    cfg = config.load_config()
    dcs = cfg.get("dc", {})
    if dcs:
        _echo("Per-realm KDC:")
        for realm, ip in sorted(dcs.items()):
            _echo(f"  {realm:28} {ip}")
    else:
        _echo("No per-realm DCs configured.  Set one: krbvault config dc <REALM> <IP>")
    _echo(f"(config file: {config.config_path()})")
    return 0


def cmd_env(args) -> int:
    print(config.shell_env_line())
    return 0


def cmd_passwd(args) -> int:
    store = _unlock(_open_store(args))
    new = _prompt_passphrase(confirm=True)
    store.change_passphrase(new)
    agent.stop(store.path)
    store.close()
    _ok("Passphrase changed. Re-unlock when ready.")
    return 0


# --- parser ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="krbvault",
        description="Encrypted, identity-keyed store for Kerberos tickets and "
                    "credentials (authorized engagements only).")
    p.add_argument("--version", action="version", version=f"krbvault {__version__}")
    p.add_argument("-e", "--engagement", help="engagement name (vault file)")
    p.add_argument("--store", help="explicit path to the .kvault file")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="when to colourise output (default: auto — only on a TTY)")
    p.add_argument("--no-color", dest="no_color", action="store_true",
                   help="disable colour (same as --color never)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="create a new vault")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("status", help="show vault summary")
    sp.add_argument("--json", action="store_true", help="machine-readable JSON")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("unlock", help="start the unlock agent")
    sp.add_argument("--ttl", type=int, default=28800, help="seconds to stay unlocked (default 8h)")
    sp.set_defaults(func=cmd_unlock)

    sp = sub.add_parser("lock", help="stop the unlock agent")
    sp.set_defaults(func=cmd_lock)

    sp = sub.add_parser("import", help="import a ccache/kirbi ticket file")
    sp.add_argument("file")
    sp.add_argument("--identity", help="override identity (principal@REALM)")
    sp.add_argument("--source", help="provenance note")
    sp.add_argument("--replace", action="store_true",
                    help="supersede existing tickets of the same kind+SPN for the identity")
    sp.set_defaults(func=cmd_import)

    sp = sub.add_parser("request", aliases=["req"],
                        help="request a TGT (or TGS with --spn) from stored material")
    sp.add_argument("identity", help="principal@REALM")
    sp.add_argument("--spn", help="request a service ticket for this SPN instead of a TGT")
    sp.add_argument("--impersonate", metavar="USER",
                    help="S4U: get the --spn ticket as this user (constrained delegation); "
                         "identity is the service account that holds the TGT/key")
    sp.add_argument("--ctype", help="which stored credential to mint from (aes256/nt/password/...)")
    sp.add_argument("--pfx", action="store_true", help="PKINIT: get a TGT from the stored certificate (PFX)")
    sp.add_argument("--pfx-pass", dest="pfx_pass", help="password for the stored PFX, if any")
    sp.add_argument("--dc", help="KDC host or IP (else per-realm config, then DNS)")
    sp.add_argument("--replace", action="store_true",
                    help="supersede existing tickets of the same kind+SPN")
    sp.set_defaults(func=cmd_request)

    sp = sub.add_parser("renew", help="renew a renewable TGT")
    sp.add_argument("selector", help="principal@REALM or #<ticket-id>")
    sp.add_argument("--dc", help="KDC host or IP (else per-realm config)")
    sp.add_argument("--replace", action="store_true",
                    help="supersede the old TGT with the renewed one")
    sp.set_defaults(func=cmd_renew)

    sp = sub.add_parser("add", help="add a credential to an identity")
    sp.add_argument("identity", help="principal@REALM")
    sp.add_argument("--password")
    sp.add_argument("--nt", help="NTLM hash (hex)")
    sp.add_argument("--aes256")
    sp.add_argument("--aes128")
    sp.add_argument("--rc4")
    sp.add_argument("--des")
    sp.add_argument("--aeskey")
    sp.add_argument("--pfx", help="path to a PFX/PKCS#12 file")
    sp.add_argument("--source", help="provenance note")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("ls", aliases=["list"], help="list identities grouped by domain")
    sp.add_argument("--domain", help="filter to one realm")
    sp.add_argument("--json", action="store_true", help="machine-readable JSON")
    sp.set_defaults(func=cmd_ls)

    sp = sub.add_parser("describe", aliases=["show", "info"], help="show an identity or #ticket")
    sp.add_argument("selector", help="principal@REALM or #<ticket-id>")
    sp.add_argument("--json", action="store_true", help="machine-readable JSON")
    sp.set_defaults(func=cmd_describe)

    sp = sub.add_parser("use", help="make a ticket the active KRB5CCNAME")
    sp.add_argument("selector", help="principal@REALM or #<ticket-id>")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--export", action="store_true", help="print export line instead (parallel shells)")
    g.add_argument("--shell", action="store_true", help="drop into a subshell scoped to this ticket")
    sp.add_argument("--for", dest="for_tool", choices=emit.TOOLS, help="also print tool flags")
    sp.add_argument("--target", help="target host for emitted flags")
    sp.set_defaults(func=cmd_use)

    sp = sub.add_parser("emit", help="print ready-to-run tool flags for an identity")
    sp.add_argument("identity", help="principal@REALM")
    sp.add_argument("--for", dest="for_tool", choices=emit.TOOLS, required=True)
    sp.add_argument("--target", help="target host")
    sp.set_defaults(func=cmd_emit)

    sp = sub.add_parser("reveal", help="print a stored credential value")
    sp.add_argument("identity", help="principal@REALM")
    sp.add_argument("--ctype", help="only this credential type")
    sp.set_defaults(func=cmd_reveal)

    sp = sub.add_parser("rm", aliases=["delete"],
                        help="delete an identity, a #ticket, or one credential (--ctype)")
    sp.add_argument("selector")
    sp.add_argument("--ctype", help="with an identity: remove just this credential type")
    sp.set_defaults(func=cmd_rm)

    sp = sub.add_parser("export", help="write a stored ticket out to a .ccache/.kirbi file")
    sp.add_argument("selector", help="principal@REALM or #<ticket-id>")
    sp.add_argument("--kirbi", action="store_true", help="export as .kirbi instead of .ccache")
    sp.add_argument("-o", "--output", help="output path (default: <client>_<kind>_<id>.<ext>)")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("purge", help="delete expired tickets (optionally for one identity)")
    sp.add_argument("selector", nargs="?", help="limit to this principal@REALM")
    sp.set_defaults(func=cmd_purge)

    sp = sub.add_parser("config", help="show or set per-realm defaults (e.g. KDC)")
    csub = sp.add_subparsers(dest="action")
    cdc = csub.add_parser("dc", help="set the KDC host/IP for a realm")
    cdc.add_argument("realm")
    cdc.add_argument("ip", nargs="?")
    cdc.add_argument("--unset", action="store_true", help="remove the DC for this realm")
    sp.set_defaults(func=cmd_config)

    sp = sub.add_parser("env", help="print the KRB5CCNAME export line")
    sp.set_defaults(func=cmd_env)

    sp = sub.add_parser("passwd", help="change the vault passphrase")
    sp.set_defaults(func=cmd_passwd)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_output(getattr(args, "color", "auto"), getattr(args, "no_color", False))
    try:
        return args.func(args)
    except (StoreError, LockedError) as exc:
        _err(str(exc))
        return 1
    except BadPassphrase:
        _err("wrong passphrase")
        return 1
    except (kerberos.KerberosError, request.RequestError) as exc:
        _err(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
