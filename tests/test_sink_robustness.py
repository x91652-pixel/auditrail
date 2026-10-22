"""An anchors file or witness copy that exists but cannot be read is SINK_UNREACHABLE, never a crash or a pass."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from auditrail import Ledger, Signer
from auditrail.anchor import FileSink, anchor_ledger
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def world(tmp_path):
    signer = Signer.from_seed(bytes(range(32)))
    led = Ledger(tmp_path / "l.jsonl", signer=signer, fsync=False)
    for i in range(3):
        led.record(agent_id="a", session_id="s", policy_version="p", policy_hash="ab" * 32, tool="x",
                   categories=["c"], args={"i": i}, decision="allow")
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(tmp_path / "w.jsonl"), signer=signer)
    return tmp_path, {signer.key_id: signer.public_hex}


def test_a_witness_that_is_a_directory_is_unreachable(world):
    w, keys = world
    (w / "wdir").mkdir()
    res = verify_all(w / "l.jsonl", public_keys=keys, witness_path=w / "wdir")
    assert res["status"] == "SINK_UNREACHABLE" and "witness file could not be read" in res["detail"]


def test_an_anchors_file_that_is_a_directory_is_unreachable(world):
    w, keys = world
    (w / "adir").mkdir()
    res = verify_all(w / "l.jsonl", public_keys=keys, anchors_path=w / "adir")
    assert res["status"] == "SINK_UNREACHABLE" and "anchors file could not be read" in res["detail"]


@pytest.mark.skipif(os.name != "nt", reason="Windows refuses to open a file another handle holds without sharing")
def test_a_witness_locked_by_another_process_is_unreachable(world):
    w, keys = world
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import ctypes,sys,time\n"
         "k=ctypes.windll.kernel32\n"
         "k.CreateFileW.restype=ctypes.c_void_p\n"
         "h=k.CreateFileW(sys.argv[1],0x80000000,0,None,3,0x80,None)\n"
         "print('locked' if h not in (None,ctypes.c_void_p(-1).value) else 'failed',flush=True)\n"
         "time.sleep(60)", str(w / "w.jsonl")],
        stdout=subprocess.PIPE, text=True)
    try:
        if holder.stdout.readline().strip() != "locked":
            pytest.skip("could not take an exclusive handle on this system")
        res = verify_all(w / "l.jsonl", public_keys=keys, witness_path=w / "w.jsonl")
        assert res["status"] == "SINK_UNREACHABLE"
    finally:
        holder.kill()
        holder.wait()
        holder.stdout.close()


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="chmod 000 is only enforced for a non-root POSIX user")
def test_an_unreadable_witness_by_permission_is_unreachable(world):
    w, keys = world
    (w / "w.jsonl").chmod(0)
    try:
        res = verify_all(w / "l.jsonl", public_keys=keys, witness_path=w / "w.jsonl")
        assert res["status"] == "SINK_UNREACHABLE"
    finally:
        (w / "w.jsonl").chmod(0o600)


# --- an explicit --anchors path that is not a file is an unreadable input
def _cli(*argv):
    r = subprocess.run([sys.executable, "-m", "auditrail.cli", *map(str, argv)], cwd=ROOT, capture_output=True, timeout=120)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def test_verify_with_a_missing_anchors_file_is_exit_2_with_one_line(world):
    w, keys = world
    code, out, err = _cli("verify", w / "l.jsonl", "--anchors", w / "nope.jsonl")
    assert code == 2 and out.strip() == ""
    lines = [x for x in err.splitlines() if x.strip()]
    assert len(lines) == 1 and lines[0].startswith("[ERROR] ") and "nope.jsonl" in lines[0]
    assert "file not found" in lines[0] and "leave out --anchors" in lines[0]
    assert "Traceback" not in err


def test_verify_with_an_anchors_directory_is_also_exit_2(world):
    w, keys = world
    (w / "adir").mkdir()
    code, out, err = _cli("verify", w / "l.jsonl", "--anchors", w / "adir")
    assert code == 2 and "[ERROR]" in err
    assert "not a file" in err and "file not found" not in err
    # a path that does not exist keeps the old wording
    code, out, err = _cli("verify", w / "l.jsonl", "--anchors", w / "nope.jsonl")
    assert code == 2 and "file not found" in err and "not a file" not in err


def test_without_anchors_and_with_a_real_anchors_file_nothing_changes(world):
    w, keys = world
    assert _cli("verify", w / "l.jsonl")[0] == 0
    code, out, err = _cli("verify", w / "l.jsonl", "--anchors", w / "a.jsonl")
    assert code in (0, 1) and "[ERROR]" not in err


def test_creating_a_new_anchors_file_with_the_anchor_command_still_works(world):
    w, keys = world
    code, out, err = _cli("anchor", "--ledger", w / "l.jsonl", "--anchors", w / "new-anchors.jsonl")
    assert code == 0 and (w / "new-anchors.jsonl").exists(), (out, err)
