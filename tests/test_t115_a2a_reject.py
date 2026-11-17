"""0.3.4 item 9 (B-F5): a malformed, unauthenticated envelope is always a SignatureError with a short rejection record."""
import pytest

from auditrail import Guard, Ledger, PolicyEngine, Signer
from auditrail.agent_bridge import ReplayGuard, SignatureError, send_envelope
from auditrail.keys import KeyRegistry

A = Signer.from_seed(bytes([1]) * 32)
B = Signer.from_seed(bytes([2]) * 32)
REG = KeyRegistry({"A": A.public_hex, "B": B.public_hex})
POL = {"version": "p", "agents": {}, "default": {"allowed_tools": []}}
GOOD = send_envelope(A, "A", "B", {"x": 1}, "t1", categories=["data_access"])


@pytest.mark.parametrize("name,env", [
    ("sender list", {**GOOD, "sender": ["A"]}),
    ("sender null", {**GOOD, "sender": None}),
    ("sender number", {**GOOD, "sender": 5}),
    ("sender lone surrogate", {**GOOD, "sender": "\ud800"}),
    ("sender 2 MB", {**GOOD, "sender": "S" * 2_000_000}),
    ("msg_id 2 MB", {**GOOD, "sender": "nobody", "msg_id": "M" * 2_000_000}),
    ("msg_id lone surrogate", {**GOOD, "sender": "nobody", "msg_id": "\udc00"}),
])
def test_malformed_envelopes_are_rejected_with_a_short_record(tmp_path, name, env):
    p = tmp_path / "l.jsonl"
    g = Guard(PolicyEngine(POL), Ledger(p, fsync=False))
    with pytest.raises(SignatureError):
        g.receive_message(env, REG, "B", B, ReplayGuard())
    recs = [r for r in Ledger(p)]
    assert len(recs) == 1 and recs[0]["status"] == "rejected"
    assert len(recs[0].get("peer") or "") <= 200 and len(recs[0].get("msg_id") or "") <= 200
    assert len(recs[0]["reason"]) <= 1200
    assert p.stat().st_size < 4000


def test_a_valid_envelope_is_still_accepted(tmp_path):
    g = Guard(PolicyEngine(POL), Ledger(tmp_path / "l.jsonl", fsync=False))
    fresh = send_envelope(A, "A", "B", {"x": 1}, "t1", categories=["data_access"])  # built now: envelopes expire in 60 s
    session, payload, receipt = g.receive_message(fresh, REG, "B", B, ReplayGuard())
    assert payload == {"x": 1}
