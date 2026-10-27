"""P1-P3 follow-ups to the stage 2 review: lone surrogates, limits the library itself can reach, origin in the spec."""
import pytest

# these tests wrap many tools without a category on purpose; the warning is not what they are about
pytestmark = pytest.mark.filterwarnings("ignore:tool .* is wrapped with no category")

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


# ---------------------------------------------------------------------------------------------- P2
from auditrail import Guard, PolicyEngine, RemoteLedger  # noqa: E402

CFG = {"version": "p2", "agents": {"a": {"allowed_tools": ["boom"] + [f"t{i}" for i in range(1100)],
                                          "tool_categories": {}}},
       "default": {"allowed_tools": [], "enforce_lethal_trifecta": True}}


def test_p2_a_very_long_exception_message_is_truncated_with_a_digest_and_does_not_hide_the_original(tmp_path):
    svc, ledger, signer = recorder(tmp_path)
    try:
        guard = Guard(PolicyEngine(CFG), RemoteLedger(port=svc.address[1], token="t"), record_error_text=True)

        def boom():
            raise ValueError("x" * 20000)

        with pytest.raises(ValueError):  # the tool's own error, not RecorderUnavailable
            guard.guarded_tool("boom")(boom)(guard.session("a"))
        rec = [r for r in ledger if r["kind"] == "call"][0]
        assert rec["decision"] == "error" and len(rec["reason"]) <= 8192
        assert rec["reason"].startswith("ValueError: xxx") and "truncated from 20" in rec["reason"] and "sha256:" in rec["reason"]
        guard.ledger.close()
    finally:
        svc.stop()


def test_p2_a_guard_with_1100_tools_gets_its_heartbeat_accepted(tmp_path):
    svc, ledger, signer = recorder(tmp_path)
    try:
        guard = Guard(PolicyEngine(CFG), RemoteLedger(port=svc.address[1], token="t"))
        for i in range(1100):
            guard.guarded_tool(f"t{i}")(lambda: None)
        guard.heartbeat()
        beat = [r for r in ledger if r["kind"] == "heartbeat" and r["recorder_id"].startswith("guard-")][0]
        assert len(beat["tools"]) == 1100
        guard.ledger.close()
    finally:
        svc.stop()


def test_p2_a_short_error_text_is_unchanged(tmp_path):
    guard = Guard(PolicyEngine(CFG), Ledger(tmp_path / "l.jsonl", fsync=False), record_error_text=True)
    assert guard._reason_for(ValueError("small")) == "ValueError: small"
