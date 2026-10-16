"""End-to-end ticket handling against a real ccache.

If impacket's ticketer is available and working we forge a golden ticket to a
ccache and run it through detection, metadata extraction, single-credential
splitting, and ccache<->kirbi conversion. If ticketer is missing or can't run
(e.g. an impacket version mismatch on the host), these tests skip rather than
error — the real exercise of this path is importing a live ticket from a lab.
"""
import shutil
import subprocess

import pytest

from krbvault import kerberos

ticketer = shutil.which("ticketer.py") or shutil.which("impacket-ticketer")
pytestmark = pytest.mark.skipif(
    ticketer is None or not kerberos._HAVE_IMPACKET,
    reason="impacket ticketer not available")


@pytest.fixture
def ccache_bytes(tmp_path):
    try:
        proc = subprocess.run(
            [ticketer, "-nthash", "aad3b435b51404eeaad3b435b51404ee",
             "-domain-sid", "S-1-5-21-1-2-3", "-domain", "corp.local", "Administrator"],
            cwd=tmp_path, capture_output=True)
    except OSError as exc:
        pytest.skip(f"could not run ticketer: {exc}")
    out = tmp_path / "Administrator.ccache"
    if proc.returncode != 0 or not out.exists():
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        pytest.skip("ticketer failed to generate a fixture (likely an impacket "
                    f"version mismatch): {tail[-1] if tail else 'unknown error'}")
    return out.read_bytes()


def test_detect_and_parse(ccache_bytes):
    assert kerberos.detect_format(ccache_bytes) == "ccache"
    cc = kerberos.load_ccache(ccache_bytes)
    metas = kerberos.describe_credentials(cc)
    assert len(metas) == 1
    m = metas[0]
    assert m["kind"] == "TGT"
    assert m["client"] == "Administrator"
    assert m["client_realm"] == "CORP.LOCAL"
    assert m["server"].lower().startswith("krbtgt/")
    assert m["end_time"] is not None


def test_split_and_roundtrip(ccache_bytes):
    cc = kerberos.load_ccache(ccache_bytes)
    blobs = kerberos.split_single_credentials(cc)
    assert len(blobs) == 1
    # each split blob re-parses as a ccache with one credential
    cc2 = kerberos.load_ccache(blobs[0])
    assert len(kerberos.describe_credentials(cc2)) == 1
    # ccache -> kirbi -> ccache
    kirbi = kerberos.to_kirbi_bytes(cc)
    assert kerberos.detect_format(kirbi) == "kirbi"
    cc3 = kerberos.load_ccache(kirbi)
    assert len(cc3.credentials) == 1
