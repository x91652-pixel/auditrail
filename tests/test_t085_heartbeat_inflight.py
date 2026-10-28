"""T-085 S1: a heartbeat never reports a request that is still being written as received-but-not-recorded."""
import threading
import time

from auditrail import Ledger, RecorderService
from auditrail.recorder import call_fields

THREADS, REQUESTS = 6, 900


def test_every_heartbeat_has_attempted_equal_recorded(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    svc = RecorderService(ledger, port=0, heartbeat_s=0)
    real_append = ledger.append_call
    n = [0]
    n_lock = threading.Lock()

    def flaky(fields, origin=None):
        with n_lock:
            n[0] += 1
            fail = n[0] % 2 == 0
        time.sleep(0.0005)  # a write that takes time, so heartbeats land while requests are in flight
        if fail:
            raise OSError("disk full")
        return real_append(fields, origin=origin)

    beats = []

    def fake_heartbeat(**kw):
        beats.append((kw["calls_attempted"], kw["calls_recorded"]))
        return {"seq": 0, "hash": "0" * 64}

    ledger.append_call = flaky
    ledger.record_heartbeat = fake_heartbeat
    req = {"op": "call", "fields": call_fields(agent_id="a", session_id="s", policy_version="v1", tool="t",
                                              categories=[], args={}, decision="allow", result={})}
    done = threading.Event()
    ok = [0]

    def worker(count):
        for _ in range(count):
            if svc.handle_request(req)["ok"]:
                with n_lock:
                    ok[0] += 1

    def beater():
        while not done.is_set():
            svc.heartbeat()
            time.sleep(0.0003)

    b = threading.Thread(target=beater)
    b.start()
    ts = [threading.Thread(target=worker, args=(REQUESTS // THREADS,)) for _ in range(THREADS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    done.set()
    b.join()
    svc.heartbeat()  # final: whatever was carried over
    assert len(beats) > 5, "the heartbeats must actually interleave with the requests"
    bad = [x for x in beats if x[0] != x[1]]
    assert not bad, f"{len(bad)} of {len(beats)} heartbeats had attempted != recorded, e.g. {bad[:3]}"
    assert sum(a for a, _ in beats) == ok[0] == REQUESTS // 2
