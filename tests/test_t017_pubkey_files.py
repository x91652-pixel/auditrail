"""T-017 R-2: a .pub file is read by the same rule in Python and in Rust.

The rule (what the Rust verifier did all along): trim surrounding Unicode whitespace, then the rest must be
exactly 64 hexadecimal digits (upper or lower case). Python used to accept embedded whitespace and any
length (bytes.fromhex ignores whitespace and checks neither).
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from auditrail import Ledger, Signer
from auditrail.keys import key_id_for, load_public_keys

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")

KEY = Signer.from_seed(bytes(range(32)))
HEX = KEY.public_hex

# name -> (bytes of the file, accepted?)
VARIANTS = {
    "original": (HEX.encode() + b"\n", True),
    "no-newline": (HEX.encode(), True),
    "all-caps": (HEX.upper().encode() + b"\n", True),
    "mixed-case": ((HEX[:20].upper() + HEX[20:]).encode(), True),
    "surrounding-whitespace": (b"  \r\n\t" + HEX.encode() + b" \r\n\n", True),
    "no-break-space-around": ((" " + HEX + " \n").encode("utf-8"), True),
    "ideographic-space-around": (("　" + HEX + "　").encode("utf-8"), True),
    "file-separator-control-char": (HEX.encode() + b"\x1c", False),   # not White_Space for Rust's trim
    "embedded-space": ((HEX[:32] + " " + HEX[32:]).encode(), False),
    "embedded-newline": ((HEX[:32] + "\n" + HEX[32:]).encode(), False),
    "embedded-tab": ((HEX[:10] + "\t" + HEX[10:]).encode(), False),
    "0x-prefix": (b"0x" + HEX.encode(), False),
    "odd-length": (HEX[:-1].encode(), False),
    "too-short-31-bytes": (HEX[:62].encode(), False),
    "too-long-33-bytes": (HEX.encode() + b"00", False),
    "empty": (b"", False),
    "only-whitespace": (b" \n", False),
    "non-hex-character": ((HEX[:-1] + "g").encode(), False),
    "invalid-utf8": (HEX.encode() + b"\xff", False),
    "two-keys-on-two-lines": (HEX.encode() + b"\n" + HEX.encode() + b"\n", False),
}


@pytest.fixture(scope="module")
def ledger_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("pub") / "l.jsonl"
    led = Ledger(path, signer=KEY, fsync=False)
    led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=["internal"],
               args={"i": 1}, decision="allow", reason=None)
    return path


def python_accepts(path):
    try:
        keys = load_public_keys([path])
    except (ValueError, UnicodeDecodeError):
        return False, None
    return True, keys


def rust_accepts(ledger, pub):
    out = subprocess.run([str(BINARY), str(ledger), "--pubkey", str(pub), "--json"], capture_output=True,
                         text=True, encoding="utf-8", errors="replace")
    if out.returncode == 2:  # the key file (or the ledger) could not be used
        return False
    return json.loads(out.stdout)["status"] == "OK"


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_r2_python_accepts_exactly_the_key_files_the_rule_allows(tmp_path, name):
    content, accepted = VARIANTS[name]
    p = tmp_path / "k.pub"
    p.write_bytes(content)
    ok, keys = python_accepts(p)
    assert ok is accepted, name
    if accepted:
        assert keys == {key_id_for(HEX): HEX}, "key and key id are the same whatever the spelling"


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_r2_python_and_rust_agree_on_every_variant(tmp_path, ledger_path, name):
    content, accepted = VARIANTS[name]
    p = tmp_path / "k.pub"
    p.write_bytes(content)
    py, _ = python_accepts(p)
    assert py is accepted
    if BINARY is None:
        pytest.skip("Rust verifier not built; the Python half above passed, the Rust half did not run")
    assert rust_accepts(ledger_path, p) is accepted, f"Rust disagrees on {name!r}"


def test_r2_the_signing_key_file_loader_is_still_lenient_and_is_reported_not_changed(tmp_path):
    """Signer.from_file (the PRIVATE key) still reads with strip() + bytes.fromhex. Pinned so that tightening it
    is a deliberate change; see the T-017 report."""
    seed = KEY.seed_hex()
    p = tmp_path / "k.key"
    p.write_text(seed[:32] + " " + seed[32:] + "\n", encoding="utf-8")
    assert Signer.from_file(p).public_hex == HEX
