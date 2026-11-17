"""0.3.4 item 4 (B-F3): Guard.heartbeat must not report a call that is still running as intercepted-but-not-recorded."""
import threading
import time

from auditrail import Guard, Ledger, PolicyEngine, Signer
from auditrail.verifier import verify_all

POL = {"version": "p", "agents": {"a": {"allowed_tools": ["slow", "boom"],
                                        "tool_categories": {"slow": ["internal"], "boom": ["internal"]}}},
       "default": {"allowed_tools": []}}


def beats(path):
    return [(h["calls_attempted"], h["calls_recorded"]) for h in Ledger(path) if h["kind"] == "heartbeat"]


def test_a_heartbeat_during_a_running_call_is_consistent_and_the_call_is_counted_next(tmp_path):
    sg = Signer.from_seed(bytes(range(32)))
    p = tmp_path / "g.jsonl"
    g = Guard(PolicyEngine(POL), Ledger(p, signer=sg, fsync=False), recorder_id="guard-test")
    gate = threading.Event()

    @g.guarded_tool("slow", categories=["internal"])
    def slow():
        gate.wait(10)
        return "done"

    s = g.session("a")
    th = threading.Thread(target=lambda: slow(s))
    th.start()
    time.sleep(0.3)
    g.heartbeat()          # the call is running: not counted yet
    gate.set()
    th.join()
    g.heartbeat()          # now it is counted, once, as recorded
    assert beats(p) == [(0, 0), (1, 1)]
    assert verify_all(p, public_keys={sg.key_id: sg.public_hex}, max_gap_s=3600)["status"] == "OK"


def test_a_call_whose_evidence_could_not_be_written_is_still_reported_as_unrecorded(tmp_path):
    sg = Signer.from_seed(bytes(range(32)))
    p = tmp_path / "g.jsonl"
    led = Ledger(p, signer=sg, fsync=False)
    g = Guard(PolicyEngine(POL), led, recorder_id="guard-test")

    @g.guarded_tool("boom", categories=["internal"])
    def boom():
        return "ran"

    real = led.record
    led.record = lambda **kw: (_ for _ in ()).throw(OSError("disk full"))
    s = g.session("a")
    try:
        boom(s)
    except OSError:
        pass
    led.record = real
    g.heartbeat()
    assert beats(p) == [(1, 0)]


def test_many_threads_and_heartbeats_never_report_a_mismatch(tmp_path):
    sg = Signer.from_seed(bytes(range(32)))
    p = tmp_path / "g.jsonl"
    led = Ledger(p, signer=sg, fsync=False)
    g = Guard(PolicyEngine(POL), led, recorder_id="guard-test")

    @g.guarded_tool("slow", categories=["internal"])
    def slow():
        time.sleep(0.002)
        return 1

    stop = threading.Event()

    def beater():
        while not stop.is_set():
            g.heartbeat()
            time.sleep(0.001)

    b = threading.Thread(target=beater)
    b.start()
    def work():
        s = g.session("a")
        for _ in range(40):
            slow(s)
    ts = [threading.Thread(target=work) for _ in range(5)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    stop.set()
    b.join()
    g.heartbeat()
    got = beats(p)
    assert sum(a for a, _ in got) == 200 and all(a == r for a, r in got), got
