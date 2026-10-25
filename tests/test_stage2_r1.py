"""R1: `auditrail recorder` on a ledger that ends in the middle of a line stops with one [ERROR] line and exit 2."""
import os
import subprocess
import sys
from pathlib import Path

from auditrail import Ledger, Signer

ROOT = Path(__file__).resolve().parents[1]


def run_recorder(tmp_path, ledger_bytes):
    key, _ = Signer.generate().save(tmp_path / "rec")
    led = tmp_path / "l.jsonl"
    led.write_bytes(ledger_bytes)
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "AUDITRAIL_RECORDER_TOKEN": "tok", "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", "auditrail.cli", "recorder", "--ledger", str(led), "--key", str(key), "--port", "0",
         "--heartbeat", "0", "--allow-loose-permissions"],
        capture_output=True, text=True, encoding="utf-8", env=env, timeout=60, cwd=tmp_path)
    return r, led


def good_ledger(tmp_path):
    led = Ledger(tmp_path / "src.jsonl", fsync=False)
    for i in range(2):
        led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=[], args={"i": i},
                   decision="allow")
    return (tmp_path / "src.jsonl").read_bytes()


def test_a_torn_ledger_stops_the_recorder_with_one_error_line_and_exit_2(tmp_path):
    torn = good_ledger(tmp_path)[:-30]
    r, led = run_recorder(tmp_path, torn)
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "Traceback" not in r.stderr and "Traceback" not in r.stdout
    lines = [x for x in r.stderr.splitlines() if x.strip()]
    assert len(lines) == 1 and lines[0].startswith("[ERROR] ")
    assert "cut short" in lines[0] and "will not repair" in lines[0] and "new ledger file" in lines[0]
    assert led.read_bytes() == torn, "the evidence is untouched"


def test_a_ledger_missing_only_its_final_newline_is_refused_the_same_way(tmp_path):
    r, led = run_recorder(tmp_path, good_ledger(tmp_path).rstrip(b"\n"))
    assert r.returncode == 2 and r.stderr.startswith("[ERROR] ") and "Traceback" not in r.stderr


def test_a_normal_ledger_still_starts_the_recorder(tmp_path):
    import signal
    import time

    key, _ = Signer.generate().save(tmp_path / "rec")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "AUDITRAIL_RECORDER_TOKEN": "tok", "PYTHONUTF8": "1"}
    flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}
    proc = subprocess.Popen(
        [sys.executable, "-m", "auditrail.cli", "recorder", "--ledger", str(tmp_path / "ok.jsonl"), "--key", str(key),
         "--port", "0", "--heartbeat", "0", "--allow-loose-permissions"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env, cwd=tmp_path, **flags)
    try:
        line = proc.stdout.readline()
        assert "listening on" in line, line
    finally:
        proc.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
