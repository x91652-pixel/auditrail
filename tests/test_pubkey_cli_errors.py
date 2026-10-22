"""`auditrail verify` and `auditrail reconcile` with a bad --pubkey file: one [ERROR] line naming the file, exit 2,
no traceback, and nothing about the good path changes."""
import subprocess
import sys
from pathlib import Path

import pytest

from auditrail import Ledger, Signer

ROOT = Path(__file__).resolve().parents[1]
GOOD_HEX = "ab" * 32

BAD = {
    "31-bytes": (("ab" * 31 + "\n").encode(), "found 62 hexadecimal digits"),
    "utf8-bom": (b"\xef\xbb\xbf" + GOOD_HEX.encode() + b"\n", "byte order mark"),
    "utf16-bom": ((GOOD_HEX + "\n").encode("utf-16"), "UTF-16 byte order mark"),
    "utf16-no-bom": ((GOOD_HEX + "\n").encode("utf-16-le"), "contains NUL bytes (often UTF-16"),
    "not-hex": (b"zz" * 32, "exactly 64 hexadecimal digits"),
    "empty": (b"", "exactly 64 hexadecimal digits"),
}


@pytest.fixture
def env(tmp_path):
    signer = Signer.from_seed(bytes(range(32)))
    led = Ledger(tmp_path / "l.jsonl", signer=signer, fsync=False)
    led.record(agent_id="a", session_id="s", policy_version="p", policy_hash="ab" * 32, tool="x",
               categories=["c"], args={}, decision="allow")
    (tmp_path / "k.pub").write_text(signer.public_hex + "\n", encoding="utf-8")
    return tmp_path


def cli(*argv):
    r = subprocess.run([sys.executable, "-m", "auditrail.cli", *map(str, argv)], cwd=ROOT, capture_output=True,
                       timeout=120)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def argv_for(command, env, pub):
    return [command, env / "l.jsonl", "--pubkey", pub]


@pytest.mark.parametrize("command", ["verify", "reconcile"])
@pytest.mark.parametrize("kind", sorted(BAD))
def test_a_malformed_public_key_file_is_a_single_error_line_with_exit_2(env, command, kind):
    content, hint = BAD[kind]
    (env / "bad.pub").write_bytes(content)
    code, out, err = cli(*argv_for(command, env, env / "bad.pub"))
    assert code == 2, (out, err)
    assert "Traceback" not in err and "Traceback" not in out
    lines = [x for x in err.splitlines() if x.strip()]
    assert len(lines) == 1, err
    assert lines[0].startswith("[ERROR] ") and "bad.pub" in lines[0]
    assert "64 hexadecimal digits" in lines[0] and hint in lines[0]
    assert out.strip() == "", "no result is printed when an input cannot be read"


@pytest.mark.parametrize("command", ["verify", "reconcile"])
def test_a_missing_public_key_file_is_a_single_error_line_with_exit_2(env, command):
    code, out, err = cli(*argv_for(command, env, env / "nope.pub"))
    assert code == 2
    lines = [x for x in err.splitlines() if x.strip()]
    assert len(lines) == 1 and lines[0].startswith("[ERROR] ") and "nope.pub" in lines[0]
    assert "Traceback" not in err


@pytest.mark.parametrize("command", ["verify", "reconcile"])
def test_the_good_path_is_unchanged(env, command):
    code, out, err = cli(*argv_for(command, env, env / "k.pub"))
    assert code == 0, (out, err)
    assert err.strip() == ""


@pytest.mark.parametrize("command", ["verify", "reconcile", "report"])
def test_help_states_what_exit_2_means(command):
    code, out, err = cli(command, "--help")
    assert code == 0
    text = " ".join(out.split())
    assert "2 = an input file" in text and "no result is produced" in text
