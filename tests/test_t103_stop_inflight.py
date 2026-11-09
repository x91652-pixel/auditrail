"""0.3.3 B3: stop() waits for requests that are still being written before its final heartbeat counts them."""
import threading
import time

from auditrail import Ledger, RecorderService
from auditrail.recorder import call_fields


def make(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    svc = RecorderService(ledger, port=0, heartbeat_s=0)
    beats = []
    ledger.record_heartbeat = lambda **kw: beats.append((kw["calls_attempted"], kw["calls_recorded"])) or {
        "seq": 0, "hash": "0" * 64}
    req = {"op": "call", "fields": call_fields(agent_id="a", session_id="s", policy_version="v1", tool="t",
                                              categories=[], args={}, decision="allow", result={})}
    return ledger, svc, beats, req


def test_final_heartbeat_counts_a_request_that_is_still_being_written(tmp_path):
    ledger, svc, beats, req = make(tmp_path)
    real = ledger.append_call
    entered, release = threading.Event(), threading.Event()

    def slow(fields, origin=None):
        entered.set()
        release.wait(10)
        return real(fields, origin=origin)

    ledger.append_call = slow
    svc.start()
    reply = []
    t = threading.Thread(target=lambda: reply.append(svc.handle_request(req)))
    t.start()
    assert entered.wait(5)
    s = threading.Thread(target=svc.stop)
    s.start()
    time.sleep(1.5)  # longer than serve_forever's 0.5 s poll, so shutdown() alone cannot explain the wait
    assert s.is_alive(), "stop() must wait for the request being written"
    release.set()
    t.join(5)
    s.join(10)
    assert not s.is_alive() and reply and reply[0]["ok"]
    assert sum(a for a, _ in beats) == 1 and sum(r for _, r in beats) == 1, beats
    assert all(a == r for a, r in beats), beats


def test_stop_gives_up_waiting_after_the_timeout(tmp_path):
    ledger, svc, beats, req = make(tmp_path)
    block = threading.Event()
    real = ledger.append_call
    entered = threading.Event()

    def stuck(fields, origin=None):
        entered.set()
        block.wait(10)
        return real(fields, origin=origin)

    ledger.append_call = stuck
    svc.start()
    t = threading.Thread(target=lambda: svc.handle_request(req), daemon=True)
    t.start()
    assert entered.wait(5)
    t0 = time.monotonic()
    svc.stop(inflight_timeout_s=0.5)
    assert 0.4 < time.monotonic() - t0 < 5
    block.set()
    t.join(5)
