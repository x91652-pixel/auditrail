"""Tests for the gaps STATUS.md listed as D7 (SECURITY.md says every claim has a test):

H3  Guard.start_heartbeats / stop_heartbeats (background thread)
H4  RecorderService periodic loop and anchor()
H5  `auditrail recorder` as a real, separate OS process, appended to through RemoteLedger
V10 `anchor --push` really pushes to a git remote (a local bare repository; no network)

Nothing here sleeps for long: intervals are tens of milliseconds and every wait is a
bounded poll on the thing being waited for.
"""
import argparse
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from auditrail import Guard, Ledger, PolicyEngine, RecorderService, RemoteLedger, Signer
from auditrail.anchor import FileSink
from auditrail.cli import main as cli_main
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git executable not available")

POLICY = {"version": "d7", "agents": {"a": {"allowed_tools": ["work"], "tool_categories": {"work": ["internal"]}}}}


def wait_for(cond, timeout=10.0, step=0.02):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


def kinds(ledger_or_path, kind):
    led = ledger_or_path if isinstance(ledger_or_path, Ledger) else Ledger(ledger_or_path)
    return [r for r in led if r.get("kind") == kind]


def heartbeat_threads():
    return [t for t in threading.enumerate() if t.name == "auditrail-heartbeat" and t.is_alive()]


# ============================================================ H3: Guard heartbeats

@pytest.fixture
def guard(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", fsync=False)
    g = Guard(PolicyEngine(POLICY), ledger, recorder_id="d7")
    yield g
    g.stop_heartbeats(final=False)  # never leave a thread behind, even when an assertion fails


def test_h3_background_heartbeats_keep_arriving_and_the_final_one_is_written_on_stop(guard):
    guard.start_heartbeats(0.05)
    assert wait_for(lambda: len(kinds(guard.ledger, "heartbeat")) >= 3), "no periodic heartbeats were written"
    before_stop = len(kinds(guard.ledger, "heartbeat"))
    guard.stop_heartbeats(final=True)
    assert len(kinds(guard.ledger, "heartbeat")) >= before_stop + 1, "stop(final=True) must write a last heartbeat"
    assert list(guard.ledger)[-1]["kind"] == "heartbeat"
    time.sleep(0.25)  # the loop thread may have been mid-write when stop was called; let it finish
    settled = len(kinds(guard.ledger, "heartbeat"))
    time.sleep(0.4)  # several intervals
    assert len(kinds(guard.ledger, "heartbeat")) == settled, "heartbeats kept coming after stop"


def test_h3_stop_without_final_writes_nothing_and_stops_the_thread(guard):
    guard.start_heartbeats(0.05)
    assert wait_for(lambda: len(kinds(guard.ledger, "heartbeat")) >= 2)
    guard.stop_heartbeats(final=False)
    assert wait_for(lambda: not heartbeat_threads()), "heartbeat thread is still alive after stop"
    settled = len(kinds(guard.ledger, "heartbeat"))
    time.sleep(0.3)
    assert len(kinds(guard.ledger, "heartbeat")) == settled


def test_h3_starting_twice_does_not_start_a_second_thread(guard):
    base = len(heartbeat_threads())
    guard.start_heartbeats(0.05)
    guard.start_heartbeats(0.05)
    assert len(heartbeat_threads()) == base + 1


def test_h3_can_be_restarted_after_a_stop(guard):
    guard.start_heartbeats(0.05)
    guard.stop_heartbeats(final=False)
    assert wait_for(lambda: not heartbeat_threads())
    n = len(kinds(guard.ledger, "heartbeat"))
    guard.start_heartbeats(0.05)
    assert wait_for(lambda: len(kinds(guard.ledger, "heartbeat")) > n)


def test_h3_the_heartbeats_describe_the_wrapped_tools_and_the_ledger_verifies(guard, tmp_path):
    work = guard.guarded_tool("work", categories=["internal"])(lambda *a: "ok")
    work(guard.session("a"))
    guard.start_heartbeats(0.05)
    assert wait_for(lambda: len(kinds(guard.ledger, "heartbeat")) >= 2)
    guard.stop_heartbeats(final=True)
    beats = kinds(guard.ledger, "heartbeat")
    assert all(b["tools"] == ["work"] and b["recorder_id"] == "d7" for b in beats)
    assert sum(b["calls_attempted"] for b in beats) == 1  # counted once, then reset
    assert sum(b["calls_recorded"] for b in beats) == 1
    assert verify_all(tmp_path / "l.jsonl", max_gap_s=30)["status"] == "OK"


# ============================================================ H4: recorder loop and anchor()

def _service(tmp_path, **kw):
    signer = Signer.generate()
    ledger = Ledger(tmp_path / "l.jsonl", signer=signer, fsync=False)
    return RecorderService(ledger, **kw), signer


def test_h4_the_loop_calls_its_function_at_the_interval_until_stopped(tmp_path):
    svc, _ = _service(tmp_path, heartbeat_s=0)
    calls = []

    def fn():
        calls.append(time.monotonic())
        if len(calls) >= 4:
            svc._stop.set()

    t = threading.Thread(target=svc._loop, args=(0.01, fn), daemon=True)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive() and len(calls) == 4


def test_h4_a_failing_beat_does_not_kill_the_loop(tmp_path):
    svc, _ = _service(tmp_path, heartbeat_s=0)
    calls = []

    def fn():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("one missed beat")
        if len(calls) >= 3:
            svc._stop.set()

    t = threading.Thread(target=svc._loop, args=(0.01, fn), daemon=True)
    t.start()
    t.join(timeout=10)
    assert len(calls) == 3


def test_h4_start_wires_the_heartbeat_loop_and_stop_writes_a_final_beat(tmp_path):
    svc, signer = _service(tmp_path, heartbeat_s=1)
    svc.start()
    try:
        # start() writes one itself; the loop adds one per second
        assert wait_for(lambda: len(kinds(svc.ledger, "heartbeat")) >= 2, timeout=10), "loop never wrote a heartbeat"
    finally:
        n = len(kinds(svc.ledger, "heartbeat"))
        svc.stop()
    assert len(kinds(svc.ledger, "heartbeat")) >= n + 1
    assert verify_all(tmp_path / "l.jsonl", public_keys={signer.key_id: signer.public_hex})["status"] == "OK"


def test_h4_anchor_writes_a_signed_anchor_that_verify_accepts_and_chains(tmp_path):
    anchors, witness = tmp_path / "anchors.jsonl", tmp_path / "witness.jsonl"
    svc, signer = _service(tmp_path, heartbeat_s=0, anchors_path=str(anchors), sink=FileSink(witness))
    svc.start()
    try:
        first = svc.anchor()
        assert first is not None and first["anchor"]["seq"] == len(list(svc.ledger)) - 1
        svc.heartbeat()  # a new head, so a second anchor is due
        second = svc.anchor()
        assert second["anchor"]["seq"] > first["anchor"]["seq"]
        assert second["anchor"]["prev_anchor"] == first["anchor"]["anchor_hash"]
    finally:
        svc._server.shutdown()
        svc._server.server_close()
    res = verify_all(tmp_path / "l.jsonl", public_keys={signer.key_id: signer.public_hex},
                     anchors_path=anchors, sinks={"file": FileSink(witness)}, witness_path=witness)
    assert res["status"] == "OK" and res["unanchored_tail"] == 0
    assert len(witness.read_text(encoding="utf-8").splitlines()) == 2


def test_h4_anchor_does_nothing_without_a_path_or_with_an_empty_ledger(tmp_path):
    svc, _ = _service(tmp_path, heartbeat_s=0)  # no anchors_path
    assert svc.anchor() is None
    (tmp_path / "x").mkdir()
    svc2, _ = _service(tmp_path / "x", heartbeat_s=0, anchors_path=str(tmp_path / "x" / "a.jsonl"))
    assert svc2.anchor() is None  # empty ledger: nothing to anchor yet, and no exception


def test_h4_the_periodic_anchor_loop_produces_a_verifiable_anchor(tmp_path):
    anchors = tmp_path / "anchors.jsonl"
    svc, signer = _service(tmp_path, heartbeat_s=0, anchors_path=str(anchors), anchor_s=1)
    svc.start()
    try:
        assert wait_for(lambda: anchors.exists() and anchors.read_text(encoding="utf-8").strip(), timeout=10)
    finally:
        svc.stop()
    res = verify_all(tmp_path / "l.jsonl", public_keys={signer.key_id: signer.public_hex}, anchors_path=anchors)
    assert res["status"] == "OK"


# ============================================================ H5: a real recorder process

def _spawn_recorder(tmp_path, *extra):
    key, pub = Signer.generate().save(tmp_path / "rec")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "AUDITRAIL_RECORDER_TOKEN": "d7-token",
           "PYTHONUNBUFFERED": "1"}
    flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}
    proc = subprocess.Popen(
        [sys.executable, "-m", "auditrail.cli", "recorder", "--ledger", str(tmp_path / "l.jsonl"), "--key", str(key),
         "--port", "0", "--heartbeat", "0", "--anchors", str(tmp_path / "anchors.jsonl"),
         "--witness-file", str(tmp_path / "witness.jsonl"), "--allow-loose-permissions", *extra],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", env=env, **flags)
    lines: "queue.Queue[str]" = queue.Queue()
    out: list = []

    def pump():
        try:
            for line in proc.stdout:
                out.append(line)
                lines.put(line)
        finally:
            proc.stdout.close()  # the reader owns the pipe; closing it here leaves no unclosed file behind

    threading.Thread(target=pump, daemon=True).start()
    port = None
    end = time.monotonic() + 30
    while time.monotonic() < end and port is None:
        try:
            line = lines.get(timeout=0.2)
        except queue.Empty:
            if proc.poll() is not None:
                break
            continue
        if "listening on" in line:
            port = int(line.split("listening on", 1)[1].split(";")[0].strip().rsplit(":", 1)[1])
    return proc, out, port, key, pub


def _ask_to_stop(proc):
    if os.name == "nt":
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.send_signal(signal.SIGTERM)


def _stop(proc, out, timeout):
    """Ask for a clean stop. Returns the exit code, or None if the process had to be killed."""
    _ask_to_stop(proc)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
        return None


def _use_the_recorder(port):
    remote = RemoteLedger(port=port, token="d7-token")
    g = Guard(PolicyEngine(POLICY), remote, recorder_id="agent-d7")
    work = g.guarded_tool("work", categories=["internal"])(lambda n: n * 2)
    s = g.session("a")
    assert [work(s, i) for i in range(3)] == [0, 2, 4]
    g.heartbeat()
    with pytest.raises(TypeError):
        list(remote)  # the agent side can append, never read
    remote.close()


def _keys(key, pub):
    return {Signer.from_file(key).key_id: Path(pub).read_text(encoding="utf-8").strip()}


def test_h5_a_separate_os_process_records_what_an_agent_appends(tmp_path):
    """The ledger is written by another process; it verifies from outside with only the public key.
    The recorder is stopped hard here: this test is about the separate process, not about shutdown."""
    proc, out, port, key, pub = _spawn_recorder(tmp_path)
    try:
        assert port, "recorder did not report a port:\n" + "".join(out)
        assert proc.pid != os.getpid()
        _use_the_recorder(port)
    finally:
        _stop(proc, out, timeout=0.5 if os.name == "nt" else 30)  # hard stop is enough here
    res = verify_all(tmp_path / "l.jsonl", public_keys=_keys(key, pub), anchors_path=tmp_path / "anchors.jsonl",
                     sinks={"file": FileSink(tmp_path / "witness.jsonl")}, witness_path=tmp_path / "witness.jsonl")
    assert res["status"] == "OK", res
    recs = list(Ledger(tmp_path / "l.jsonl"))
    assert sum(1 for r in recs if r["kind"] == "call") == 3
    assert {r["recorder_id"] for r in recs if r["kind"] == "heartbeat"} >= {"recorder", "agent-d7"}


def test_h5_the_stop_signal_makes_it_exit_cleanly_with_a_final_heartbeat_and_anchor(tmp_path):
    proc, out, port, key, pub = _spawn_recorder(tmp_path)
    try:
        assert port, "recorder did not report a port:\n" + "".join(out)
        _use_the_recorder(port)
    finally:
        code = _stop(proc, out, timeout=30)
    text = "".join(out)
    assert code == 0, f"exit code {code} (None = had to be killed):\n{text}"
    assert "stopped; final heartbeat and anchor written" in text
    res = verify_all(tmp_path / "l.jsonl", public_keys=_keys(key, pub), anchors_path=tmp_path / "anchors.jsonl",
                     sinks={"file": FileSink(tmp_path / "witness.jsonl")}, witness_path=tmp_path / "witness.jsonl")
    assert res["status"] == "OK" and res["unanchored_tail"] == 0, res
    last = list(Ledger(tmp_path / "l.jsonl"))[-1]
    assert last["kind"] == "heartbeat" and last["recorder_id"] == "recorder"


def test_h5_a_wrong_token_is_refused_by_the_separate_process(tmp_path):
    proc, out, port, key, pub = _spawn_recorder(tmp_path)
    try:
        assert port, "".join(out)
        from auditrail.recorder import RecorderUnavailable

        remote = RemoteLedger(port=port, token="not-the-token")
        g = Guard(PolicyEngine(POLICY), remote)
        work = g.guarded_tool("work", categories=["internal"])(lambda n: n)
        with pytest.raises(RecorderUnavailable):
            work(g.session("a"), 1)
        remote.close()
    finally:
        _stop(proc, out, timeout=0.5 if os.name == "nt" else 30)  # hard stop is enough here
    assert not [r for r in Ledger(tmp_path / "l.jsonl") if r["kind"] == "call"]


# ============================================================ V10: anchor --push

def _g(repo, *args, git_dir=None):
    base = [GIT, "--git-dir", str(git_dir)] if git_dir else [GIT, "-C", str(repo)]
    return subprocess.run([*base, "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          capture_output=True, text=True, encoding="utf-8", check=True).stdout


def _make_ledger(path, key, n=3):
    led = Ledger(path, signer=key, fsync=False)
    for i in range(n):
        led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=["internal"],
                   args={"i": i}, decision="allow", reason=None)
    return led


def _setup_repos(tmp_path):
    remote = tmp_path / "remote.git"
    work = tmp_path / "witness"
    work.mkdir()
    subprocess.run([GIT, "init", "--bare", "-q", str(remote)], check=True, capture_output=True)
    _g(work, "init", "-q")
    _g(work, "remote", "add", "origin", str(remote))
    return remote, work


def _anchor(tmp_path, work, *flags):
    return cli_main(["anchor", "--ledger", str(tmp_path / "l.jsonl"), "--anchors", str(tmp_path / "anchors.jsonl"),
                     "--git-repo", str(work), "--key", str(tmp_path / "rec.key"), *flags])


@needs_git
def test_v10_push_really_reaches_the_remote_and_the_remote_copy_verifies(tmp_path, capsys):
    remote, work = _setup_repos(tmp_path)
    key = Signer.generate()
    key.save(tmp_path / "rec")
    _make_ledger(tmp_path / "l.jsonl", key)
    assert _anchor(tmp_path, work, "--push") == 0
    branch = _g(work, "branch", "--show-current").strip()
    assert branch
    refs = _g(None, "for-each-ref", "--format=%(refname)", git_dir=remote).split()
    assert f"refs/heads/{branch}" in refs, f"nothing was pushed: {refs}"
    remote_file = _g(None, "show", f"refs/heads/{branch}:anchors/anchors.jsonl", git_dir=remote)
    local_anchor = json.loads((tmp_path / "anchors.jsonl").read_text(encoding="utf-8").splitlines()[0])
    pushed = [json.loads(x) for x in remote_file.splitlines()]
    assert pushed[0]["anchor_hash"] == local_anchor["anchor_hash"] and pushed[0]["sig"]
    # the copy that now lives outside the witness working tree is enough to verify the ledger
    clone = tmp_path / "clone"
    subprocess.run([GIT, "clone", "-q", str(remote), str(clone)], check=True, capture_output=True)
    res = verify_all(tmp_path / "l.jsonl", public_keys={key.key_id: key.public_hex},
                     witness_path=clone / "anchors" / "anchors.jsonl")
    assert res["status"] == "OK", res


@needs_git
def test_v10_a_later_anchor_is_pushed_too(tmp_path):
    remote, work = _setup_repos(tmp_path)
    key = Signer.generate()
    key.save(tmp_path / "rec")
    led = _make_ledger(tmp_path / "l.jsonl", key)
    assert _anchor(tmp_path, work, "--push") == 0
    led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=["internal"],
               args={"i": 99}, decision="allow", reason=None)
    assert _anchor(tmp_path, work, "--push") == 0
    branch = _g(work, "branch", "--show-current").strip()
    remote_file = _g(None, "show", f"refs/heads/{branch}:anchors/anchors.jsonl", git_dir=remote)
    assert len(remote_file.splitlines()) == 2
    assert _g(None, "rev-parse", f"refs/heads/{branch}", git_dir=remote) == _g(work, "rev-parse", "HEAD")


@needs_git
def test_v10_without_push_the_remote_stays_empty(tmp_path):
    remote, work = _setup_repos(tmp_path)
    key = Signer.generate()
    key.save(tmp_path / "rec")
    _make_ledger(tmp_path / "l.jsonl", key)
    assert _anchor(tmp_path, work) == 0
    assert _g(None, "for-each-ref", git_dir=remote).strip() == ""
    assert (work / "anchors" / "anchors.jsonl").exists()


@needs_git
def test_v10_a_push_that_cannot_reach_its_remote_is_reported_not_swallowed(tmp_path, capsys):
    work = tmp_path / "witness"
    work.mkdir()
    _g(work, "init", "-q")  # no remote configured
    key = Signer.generate()
    key.save(tmp_path / "rec")
    _make_ledger(tmp_path / "l.jsonl", key)
    code = _anchor(tmp_path, work, "--push")
    out = capsys.readouterr().out
    assert code != 0, out
