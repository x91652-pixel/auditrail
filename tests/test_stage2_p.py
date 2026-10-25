"""P1-P3 follow-ups to the stage 2 review: lone surrogates, limits the library itself can reach, origin in the spec."""
import pytest

from auditrail import Ledger, RecorderService, Signer
from auditrail.verifier import verify_all


def recorder(tmp_path):
    signer = Signer.generate()
    ledger = Ledger(tmp_path / "r.jsonl", signer=signer, fsync=False)
    return RecorderService(ledger, token="t", heartbeat_s=0).start(), ledger, signer


CALL = {"kind": "call", "agent_id": "a", "session_id": "s", "trace_id": "s", "policy_version": "p",
        "policy_hash": "ab" * 32, "tool": "t", "categories": ["c"], "args_digest": "cd" * 32, "decision": "allow",
        "reason": None, "result_digest": None, "duration_us": 5}


@pytest.mark.parametrize("change", [
    {"tool": "\ud800"}, {"reason": "boom \udfff"}, {"categories": ["ok", "\ud83d"]}, {"agent_id": "x\udc00y"},
])
def test_p1_a_lone_surrogate_is_refused_and_leaves_the_recorders_own_heartbeat_even(tmp_path, change):
    svc, ledger, signer = recorder(tmp_path)
    try:
        reply = svc.handle_request({"op": "call", "token": "t", "fields": {**CALL, **change}})
        assert reply["ok"] is False and "refused" in reply["error"]
        assert (svc._received, svc._written) == (0, 0)
        own = svc.heartbeat()
        assert own["calls_attempted"] == own["calls_recorded"] == 0
        keys = {signer.key_id: signer.public_hex}
        assert verify_all(tmp_path / "r.jsonl", public_keys=keys, max_gap_s=3600)["status"] == "OK"
    finally:
        svc.stop()


def test_p1_a_write_that_fails_is_not_counted_as_received(tmp_path):
    svc, ledger, signer = recorder(tmp_path)
    try:
        ledger.append_call = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        reply = svc.handle_request({"op": "call", "token": "t", "fields": CALL})
        assert reply["ok"] is False and "OSError" in reply["error"]
        assert (svc._received, svc._written) == (0, 0)
    finally:
        svc.stop()
