"""Core tests: crypto round-trips, store CRUD, format detection, lifetime math.

The Kerberos ticket-parsing path is exercised end-to-end in test_tickets.py,
which generates a real ccache with impacket-ticketer when it is available.
"""
import datetime
import json

import pytest

from krbvault import cli, crypto, kerberos, request
from krbvault.models import CredType, Ticket
from krbvault.store import Store


def test_crypto_envelope_roundtrip():
    salt = crypto.new_salt()
    kek = crypto.derive_kek("hunter2", salt)
    dek = crypto.new_dek()
    wrapped = crypto.wrap_dek(kek, dek)
    assert crypto.unwrap_dek(kek, wrapped) == dek

    blob = crypto.seal(dek, b"secret-ticket-bytes", "ticket")
    assert crypto.open_(dek, blob, "ticket") == b"secret-ticket-bytes"


def test_crypto_wrong_passphrase():
    salt = crypto.new_salt()
    dek = crypto.new_dek()
    wrapped = crypto.wrap_dek(crypto.derive_kek("right", salt), dek)
    with pytest.raises(crypto.BadPassphrase):
        crypto.unwrap_dek(crypto.derive_kek("wrong", salt), wrapped)


def test_crypto_context_binding():
    """A blob sealed under one context must not open under another."""
    dek = crypto.new_dek()
    blob = crypto.seal(dek, b"x", "cred:nt")
    with pytest.raises(crypto.BadPassphrase):
        crypto.open_(dek, blob, "ticket")


def test_store_create_unlock(tmp_path):
    path = tmp_path / "e.kvault"
    s = Store.create(path, "pw", "engagement-x")
    s.close()

    s2 = Store.open(path)
    assert s2.locked
    with pytest.raises(crypto.BadPassphrase):
        s2.unlock("nope")
    s2.unlock("pw")
    assert not s2.locked
    assert s2.engagement == "engagement-x"
    s2.close()


def test_store_credentials_and_tickets(tmp_path):
    s = Store.create(tmp_path / "e.kvault", "pw", "e")
    ident = s.add_identity("alice", "corp.local")
    assert ident.upn == "alice@CORP.LOCAL"

    cid = s.add_credential(ident.id, CredType.NT.value, b"aad3b435b51404ee", source="dump")
    ctype, val = s.reveal_credential(cid)
    assert ctype == "nt" and val == b"aad3b435b51404ee"

    t = Ticket(id=None, identity_id=ident.id, kind="TGT", client="alice",
               client_realm="CORP.LOCAL", server="krbtgt/CORP.LOCAL",
               server_realm="CORP.LOCAL", end_time="2030-01-01T00:00:00+00:00",
               blob=b"\x05\x04fake-ccache-bytes")
    tid = s.add_ticket(ident.id, t)
    assert s.reveal_ticket(tid) == b"\x05\x04fake-ccache-bytes"

    assert s.counts(ident.id) == (1, 1)
    assert [i.upn for i in s.list_identities()] == ["alice@CORP.LOCAL"]
    s.close()


def test_store_locked_blocks_writes(tmp_path):
    path = tmp_path / "e.kvault"
    Store.create(path, "pw", "e").close()
    s = Store.open(path)  # locked
    ident = s.add_identity("bob", "corp.local")  # identity metadata is fine locked
    with pytest.raises(Exception):
        s.add_credential(ident.id, "nt", b"x")  # sealing requires the DEK
    s.close()


def test_passphrase_change_preserves_data(tmp_path):
    path = tmp_path / "e.kvault"
    s = Store.create(path, "old", "e")
    ident = s.add_identity("carol", "corp.local")
    cid = s.add_credential(ident.id, "password", b"P@ssw0rd")
    s.change_passphrase("new")
    s.close()

    s2 = Store.open(path)
    with pytest.raises(crypto.BadPassphrase):
        s2.unlock("old")
    s2.unlock("new")
    assert s2.reveal_credential(cid)[1] == b"P@ssw0rd"
    s2.close()


def test_detect_format():
    assert kerberos.detect_format(b"\x05\x04\x00\x00rest") == "ccache"
    assert kerberos.detect_format(b"\x76\x82rest") == "kirbi"
    assert kerberos.detect_format(b"zzzz") == "unknown"
    assert kerberos.detect_format(b"") == "unknown"


def test_ticket_status():
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    future = (now + datetime.timedelta(hours=5)).isoformat()
    soon = (now + datetime.timedelta(minutes=5)).isoformat()
    past = (now - datetime.timedelta(hours=1)).isoformat()
    assert kerberos.ticket_status(future, now=now)[0] == "valid"
    assert kerberos.ticket_status(soon, now=now)[0] == "expiring"
    assert kerberos.ticket_status(past, now=now)[0] == "expired"
    assert kerberos.ticket_status(None, now=now)[0] == "unknown"


def test_format_timedelta():
    td = datetime.timedelta
    assert kerberos.format_timedelta(td(days=2, hours=3)) == "2d3h"
    assert kerberos.format_timedelta(td(hours=1, minutes=30)) == "1h30m"
    assert kerberos.format_timedelta(td(minutes=5)) == "5m"
    assert kerberos.format_timedelta(None) == "-"


def _json_cli(capsys, monkeypatch, store_path, home, *argv):
    monkeypatch.setenv("KRBVAULT_HOME", str(home))
    monkeypatch.setenv("KRBVAULT_STORE", str(store_path))
    rc = cli.main(list(argv))
    out = capsys.readouterr().out
    return rc, json.loads(out)


def test_cli_json_output(tmp_path, capsys, monkeypatch):
    path = tmp_path / "e.kvault"
    home = tmp_path / "home"
    s = Store.create(path, "pw", "demo")
    ident = s.add_identity("jdoe", "demo.lab", itype="user")
    s.add_credential(ident.id, "password", b"P@ss")
    s.add_credential(ident.id, "aes256", b"ab" * 32)
    t = Ticket(id=None, identity_id=ident.id, kind="TGT", client="jdoe",
               client_realm="DEMO.LAB", server="krbtgt/DEMO.LAB",
               server_realm="DEMO.LAB", flags=["renewable", "forwardable"],
               key_etype=18, etype_name="aes256_cts_hmac_sha1_96",
               end_time="2030-01-01T00:00:00+00:00",
               blob=b"\x05\x04fake")
    tid = s.add_ticket(ident.id, t)
    s.close()

    # status --json
    rc, status = _json_cli(capsys, monkeypatch, path, home, "status", "--json")
    assert rc == 0
    assert status["exists"] is True and status["engagement"] == "demo"
    assert status["identities"] == 1 and status["tickets"] == 1
    assert status["realms"] == ["DEMO.LAB"] and status["active"] is None

    # ls --json
    rc, rows = _json_cli(capsys, monkeypatch, path, home, "ls", "--json")
    assert rc == 0 and len(rows) == 1
    row = rows[0]
    assert row["upn"] == "jdoe@DEMO.LAB" and row["type"] == "user"
    assert sorted(row["credentials"]) == ["aes256", "password"]
    assert row["tickets"][0]["kind"] == "TGT"
    assert row["tickets"][0]["status"] == "valid"

    # describe <identity> --json
    rc, d = _json_cli(capsys, monkeypatch, path, home, "describe", "jdoe@demo.lab", "--json")
    assert rc == 0 and d["upn"] == "jdoe@DEMO.LAB"
    assert d["tickets"][0]["server"] == "krbtgt/DEMO.LAB"

    # describe #<id> --json
    rc, tk = _json_cli(capsys, monkeypatch, path, home, "describe", f"#{tid}", "--json")
    assert rc == 0 and tk["id"] == tid and tk["etype_num"] == 18
    assert tk["flags"] == ["renewable", "forwardable"] and tk["active"] is False


def _tgt(ident_id, etype, etype_name, end_time):
    return Ticket(id=None, identity_id=ident_id, kind="TGT", client="jdoe",
                  client_realm="DEMO.LAB", server="krbtgt/DEMO.LAB",
                  server_realm="DEMO.LAB", flags=["renewable"], key_etype=etype,
                  etype_name=etype_name, end_time=end_time, blob=b"\x05\x04x")


def test_best_tgt_prefers_fresh_aes_over_longlife_rc4(tmp_path):
    s = Store.create(tmp_path / "e.kvault", "pw", "e")
    ident = s.add_identity("jdoe", "demo.lab")
    # older, forged-style RC4 TGT with a far-future expiry (imported first)
    s.add_ticket(ident.id, _tgt(ident.id, 23, "rc4_hmac", "2036-01-01T00:00:00+00:00"))
    # newer, real AES256 TGT expiring sooner (minted second)
    aes_id = s.add_ticket(ident.id, _tgt(ident.id, 18, "aes256_cts_hmac_sha1_96",
                                         "2030-01-01T00:00:00+00:00"))
    # both auto-pickers must choose the AES ticket, not the longer-lived RC4 one
    assert cli._best_tgt(s, ident.id).id == aes_id
    assert cli._pick_ticket(s, ident.id).id == aes_id
    s.close()


def test_output_helpers():
    assert cli._flag_letters(
        ["renewable", "forwardable", "initial", "pre_authent", "proxiable"]) == "FPRIA"
    assert cli._flag_letters([]) == "-"
    assert cli._etype_short(18) == "aes256"
    assert cli._etype_short(23) == "rc4"
    assert cli._etype_short(999, "aes256_cts_hmac_sha1_96") == "aes256"
    assert cli._etype_short(None) == "?"
    txt, color = cli._expiry_short("2099-01-01T00:00:00+00:00")
    assert txt.endswith("y") and color == "green"
    assert cli._expiry_short("2000-01-01T00:00:00+00:00") == ("expired", "red")
    assert cli._expiry_short(None) == ("-", None)


def test_ls_plain_is_tab_separated(tmp_path, capsys, monkeypatch):
    s = Store.create(tmp_path / "e.kvault", "pw", "demo")
    ident = s.add_identity("jdoe", "demo.lab", itype="user")
    s.add_credential(ident.id, "password", b"x")
    s.close()
    monkeypatch.setenv("KRBVAULT_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("KRBVAULT_STORE", str(tmp_path / "e.kvault"))
    rc = cli.main(["ls"])  # capsys stdout is not a TTY -> porcelain path
    assert rc == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0].split("\t") == ["REALM", "IDENTITY", "TYPE", "CREDS", "TICKET", "EXPIRES"]
    row = next(l for l in lines if l.startswith("DEMO.LAB\t")).split("\t")
    assert row[1] == "jdoe" and row[2] == "user" and row[3] == "password"


def test_s4u_requires_getst(monkeypatch):
    monkeypatch.setattr(request, "_find_getst", lambda: None)
    with pytest.raises(request.RequestError, match="getST"):
        request.request_s4u("cifs/fs01", "demo.lab", "victim",
                            tgt_ccache=b"\x05\x04x", service_user="svc")


def test_s4u_requires_tgt(monkeypatch, tmp_path):
    monkeypatch.setattr(request, "_find_getst", lambda: str(tmp_path / "fake"))
    with pytest.raises(request.RequestError, match="TGT"):
        request.request_s4u("cifs/fs01", "demo.lab", "victim",
                            tgt_ccache=b"", service_user="svc")


def test_s4u_drives_getst_and_collects_ccache(monkeypatch, tmp_path):
    """request_s4u feeds the TGT to getST via KRB5CCNAME (no key on argv) and
    returns the ccache getST writes into its working dir."""
    fake = tmp_path / "getST.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "# getST reads the service TGT from KRB5CCNAME; assert krbvault wired it\n"
        "assert os.path.exists(os.environ['KRB5CCNAME']), 'KRB5CCNAME not set'\n"
        "assert '-k' in sys.argv and '-no-pass' in sys.argv\n"
        "imp = sys.argv[sys.argv.index('-impersonate') + 1]\n"
        "open(imp + '@cifs_fs01.ccache', 'wb').write(b'\\x05\\x04S4U-OK')\n"
    )
    fake.chmod(0o755)
    monkeypatch.setattr(request, "_find_getst", lambda: str(fake))

    out = request.request_s4u("cifs/fs01", "demo.lab", "victim",
                              tgt_ccache=b"\x05\x04tgt-bytes", service_user="svc$",
                              kdc_host="10.0.0.1")
    assert out == b"\x05\x04S4U-OK"
