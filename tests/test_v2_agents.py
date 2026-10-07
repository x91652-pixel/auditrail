"""v0.2: per-agent Ed25519 messages, receipts, reconciliation, workflow-level trifecta,
the recorder service, and the isolation fixes."""
import json
import os
import socket
import sys
import textwrap

import pytest

from auditrail import (Guard, KeyRegistry, Ledger, PolicyEngine, RecorderService, RemoteLedger, ReplayGuard, Signer,
                       SignatureError, ToolDenied, make_receipt, receive_envelope, send_envelope, verify_receipt)
from auditrail.agent_bridge import message_digest
from auditrail.reconcile import reconcile
from auditrail.recorder import RecorderUnavailable
from auditrail.verifier import verify_all

POLICY = {
    "version": "v2-test",
    "agents": {
        "A": {"allowed_tools": ["read_private", "web", "send_out", "ask_b"],
              "tool_categories": {"read_private": ["data_access"], "web": ["untrusted_input"],
                                  "send_out": ["external_comm"], "ask_b": ["agent_to_agent"]}},
        "B": {"allowed_tools": ["web", "send_out"],
              "tool_categories": {"web": ["untrusted_input"], "send_out": ["external_comm"]}},
    },
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}


@pytest.fixture
def world(tmp_path):
    a_id, b_id = Signer.generate(), Signer.generate()
    reg = KeyRegistry({"A": a_id.public_hex, "B": b_id.public_hex})
    a_rec, b_rec = Signer.generate(), Signer.generate()
    policy = PolicyEngine(POLICY)
    ga = Guard(policy, Ledger(tmp_path / "a.jsonl", signer=a_rec))
    gb = Guard(policy, Ledger(tmp_path / "b.jsonl", signer=b_rec))
    return dict(a_id=a_id, b_id=b_id, reg=reg, policy=policy, ga=ga, gb=gb, tmp=tmp_path,
                keys={a_rec.key_id: a_rec.public_hex, b_rec.key_id: b_rec.public_hex})


# ------------------------------------------------------------------ envelopes

def test_envelope_round_trip_and_receipt(world):
    env = send_envelope(world["a_id"], "A", "B", {"task": "summarise"}, "trace-1", ["data_access"])
    d = receive_envelope(env, world["reg"], "B", ReplayGuard())
    assert d.sender == "A" and d.payload == {"task": "summarise"} and d.categories == ["data_access"]
    receipt = make_receipt(world["b_id"], d)
    verify_receipt(receipt, world["reg"], message_digest(env), "B")


def test_shared_key_style_impersonation_is_impossible(world):
    # B signs a message claiming to be A: the registry says A's key is a_id, so this must fail
    forged = send_envelope(world["b_id"], "A", "B", {"approve": 9999}, "t")
    with pytest.raises(SignatureError, match="another key|signature mismatch"):
        receive_envelope(forged, world["reg"], "B", ReplayGuard())


def test_tampered_payload_redirect_unknown_sender_and_replay(world):
    rg = ReplayGuard()
    env = send_envelope(world["a_id"], "A", "B", {"n": 1}, "t")
    tampered = {**env, "payload": {"n": 2}}
    with pytest.raises(SignatureError, match="signature mismatch"):
        receive_envelope(tampered, world["reg"], "B", rg)
    with pytest.raises(SignatureError, match="addressed to"):
        receive_envelope(env, world["reg"], "C", rg)  # a message for B cannot be accepted by C
    stranger = send_envelope(Signer.generate(), "Z", "B", {}, "t")
    with pytest.raises(SignatureError, match="unknown sender"):
        receive_envelope(stranger, world["reg"], "B", rg)
    receive_envelope(env, world["reg"], "B", rg)
    with pytest.raises(SignatureError, match="replay"):
        receive_envelope(env, world["reg"], "B", rg)


def test_stale_envelope_is_rejected(world):
    env = send_envelope(world["a_id"], "A", "B", {}, "t")
    with pytest.raises(SignatureError, match="old"):
        receive_envelope(env, world["reg"], "B", ReplayGuard(), max_age_seconds=-10)


def test_receipt_for_another_message_is_rejected(world):
    e1 = send_envelope(world["a_id"], "A", "B", {"n": 1}, "t")
    e2 = send_envelope(world["a_id"], "A", "B", {"n": 2}, "t")
    r1 = make_receipt(world["b_id"], receive_envelope(e1, world["reg"], "B", ReplayGuard()))
    with pytest.raises(SignatureError):
        verify_receipt(r1, world["reg"], message_digest(e2), "B")


def test_replay_guard_forgets_old_nonces_so_memory_is_bounded():
    g = ReplayGuard(ttl_seconds=0)
    for i in range(3000):
        g.seen_before(str(i))
    assert len(g._seen) < 2100


# ------------------------------------------------------------------ workflow trifecta

def test_trifecta_split_across_two_agents_is_blocked(world):
    """A reads private data; B (a different agent) reads a web page and emails out. No single
    session holds all three, but they are one workflow: the message carries A's categories."""
    ga, gb = world["ga"], world["gb"]
    read_private = ga.guarded_tool("read_private", categories=["data_access"])(lambda x: "secret")
    web = gb.guarded_tool("web", categories=["untrusted_input"])(lambda: "attacker page")
    send_out = gb.guarded_tool("send_out", categories=["external_comm"])(lambda x: "sent")

    sa = ga.session("A")
    read_private(sa, "k")
    env = ga.send_message(sa, world["a_id"], "B", {"data": "digest-only"})
    sb, payload, receipt = gb.receive_message(env, world["reg"], "B", world["b_id"], ReplayGuard())
    assert sb.trace_id == sa.trace_id
    web(sb)
    with pytest.raises(ToolDenied, match="lethal_trifecta.*workflow"):
        send_out(sb, "leak")


def test_unlinked_sessions_still_behave_like_v01(world):
    ga = world["ga"]
    read_private = ga.guarded_tool("read_private", categories=["data_access"])(lambda: 1)
    send_out = ga.guarded_tool("send_out", categories=["external_comm"])(lambda: 1)
    read_private(ga.session("A"))
    send_out(ga.session("A"))  # different session, different trace: allowed, as before


def test_sessions_sharing_a_trace_id_share_trifecta_state(world):
    ga = world["ga"]
    rp = ga.guarded_tool("read_private", categories=["data_access"])(lambda: 1)
    web = ga.guarded_tool("web", categories=["untrusted_input"])(lambda: 1)
    out = ga.guarded_tool("send_out", categories=["external_comm"])(lambda: 1)
    rp(ga.session("A", trace_id="wf1"))
    web(ga.session("A", trace_id="wf1"))
    with pytest.raises(ToolDenied):
        out(ga.session("A", trace_id="wf1"))


def test_policy_hash_changes_with_the_rules():
    a = PolicyEngine(POLICY)
    changed = json.loads(json.dumps(POLICY))
    changed["agents"]["B"]["allowed_tools"].append("read_private")
    assert a.policy_hash != PolicyEngine(changed).policy_hash
    assert a.policy_hash == PolicyEngine(json.loads(json.dumps(POLICY))).policy_hash


# ------------------------------------------------------------------ reconcile

def _exchange(world, drop_sender_record=False, drop_receiver_record=False):
    ga, gb = world["ga"], world["gb"]
    sa = ga.session("A")
    if drop_sender_record:
        from auditrail.agent_bridge import send_envelope as raw_send
        env = raw_send(world["a_id"], "A", "B", {"x": 1}, sa.trace_id)  # bypasses the guard: nothing recorded
    else:
        env = ga.send_message(sa, world["a_id"], "B", {"x": 1})
    if drop_receiver_record:
        return env
    sb, _, receipt = gb.receive_message(env, world["reg"], "B", world["b_id"], ReplayGuard())
    if not drop_sender_record:
        ga.accept_receipt(sa, env, receipt, world["reg"])
    return env


def test_reconcile_matches_when_both_sides_recorded(world):
    _exchange(world)
    r = reconcile([world["tmp"] / "a.jsonl", world["tmp"] / "b.jsonl"], public_keys=world["keys"])
    assert r["status"] == "OK" and r["matched"] == 1 and r["findings"] == []


def test_reconcile_finds_a_message_the_sender_never_recorded(world):
    _exchange(world, drop_sender_record=True)
    r = reconcile([world["tmp"] / "a.jsonl", world["tmp"] / "b.jsonl"], agents=["A", "B"])
    assert r["status"] == "MISMATCH"
    assert [f["type"] for f in r["findings"]] == ["RECV_WITHOUT_SEND"]


def test_reconcile_finds_a_send_the_receiver_never_recorded(world):
    _exchange(world, drop_receiver_record=True)
    r = reconcile([world["tmp"] / "a.jsonl", world["tmp"] / "b.jsonl"], agents=["A", "B"])
    assert [f["type"] for f in r["findings"]] == ["SEND_WITHOUT_RECV"]


def test_reconcile_does_not_judge_agents_whose_ledger_was_not_given(world):
    _exchange(world)
    r = reconcile([world["tmp"] / "a.jsonl"])
    assert r["status"] == "OK" and r["unverifiable"] >= 1


def test_rejected_messages_are_recorded_as_evidence(world):
    gb = world["gb"]
    forged = send_envelope(world["a_id"], "A", "B", {}, "t")
    forged["payload"] = {"evil": True}
    with pytest.raises(SignatureError):
        gb.receive_message(forged, world["reg"], "B", world["b_id"], ReplayGuard())
    rec = [r for r in gb.ledger if r["kind"] == "a2a_recv"][0]
    assert rec["status"] == "rejected" and "signature mismatch" in rec["reason"]


# ------------------------------------------------------------------ recorder service

def test_recorder_holds_the_key_and_agent_side_can_only_append(tmp_path):
    rec_key = Signer.generate()
    ledger = Ledger(tmp_path / "l.jsonl", signer=rec_key)
    svc = RecorderService(ledger, heartbeat_s=0, policy_version="p", policy_hash="h").start()
    try:
        remote = RemoteLedger(port=svc.address[1])
        guard = Guard(PolicyEngine(POLICY), remote)
        tool = guard.guarded_tool("read_private", categories=["data_access"])(lambda x: {"secret": x})
        assert tool(guard.session("A"), "very-private-arg") == {"secret": "very-private-arg"}
        with pytest.raises(TypeError):
            list(remote)  # agents cannot read the ledger back
        assert not hasattr(remote, "signer") or remote.signer is None
    finally:
        svc.stop()
    r = verify_all(tmp_path / "l.jsonl", public_keys={rec_key.key_id: rec_key.public_hex})
    assert r["status"] == "OK"
    assert "very-private-arg" not in (tmp_path / "l.jsonl").read_text(encoding="utf-8")


def test_recorder_rejects_requests_without_the_token_and_non_append_ops(tmp_path):
    svc = RecorderService(Ledger(tmp_path / "l.jsonl", signer=Signer.generate()), token="s3cret", heartbeat_s=0).start()
    try:
        port = svc.address[1]
        with pytest.raises(RecorderUnavailable, match="token"):
            RemoteLedger(port=port, token="wrong").record_event("heartbeat")
        assert svc.handle_request({"op": "delete", "token": "s3cret"})["ok"] is False
        assert svc.handle_request({"op": "call", "fields": {"tool": "x"}, "token": "s3cret"}) .get("ok") is not True
    finally:
        svc.stop()


def test_guarded_call_fails_loudly_when_the_recorder_is_down():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    guard = Guard(PolicyEngine(POLICY), RemoteLedger(port=port, timeout=0.5))
    tool = guard.guarded_tool("read_private", categories=["data_access"])(lambda: 1)
    with pytest.raises(RecorderUnavailable):
        tool(guard.session("A"))


def test_recorder_refuses_non_loopback_addresses(tmp_path):
    with pytest.raises(ValueError):
        RecorderService(Ledger(tmp_path / "l.jsonl"), host="0.0.0.0")


def test_guard_heartbeat_reports_intercepted_vs_recorded(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", signer=Signer.generate())
    guard = Guard(PolicyEngine(POLICY), ledger)
    tool = guard.guarded_tool("read_private", categories=["data_access"])(lambda: 1)
    tool(guard.session("A")); tool(guard.session("A"))
    guard.heartbeat()
    beat = [r for r in ledger if r["kind"] == "heartbeat"][0]
    assert beat["calls_attempted"] == beat["calls_recorded"] == 2
    assert beat["tools"] == ["read_private"] and beat["policy_hash"] == guard.policy.policy_hash
    # a call that crashes the ledger write shows up as attempted > recorded
    ledger.record = lambda **kw: (_ for _ in ()).throw(OSError("disk full"))
    with pytest.raises(OSError):
        tool(guard.session("A"))
    del ledger.record
    guard.heartbeat()
    beat2 = [r for r in ledger if r["kind"] == "heartbeat"][1]
    assert (beat2["calls_attempted"], beat2["calls_recorded"]) == (1, 0)
    assert verify_all(tmp_path / "l.jsonl", max_gap_s=3600)["status"] == "UNRECORDED_CALLS"


# ------------------------------------------------------------------ isolation fixes

def test_isolated_env_is_an_allow_list_not_a_deny_list(monkeypatch):
    from auditrail.sandbox import _isolated_env

    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@h/db")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/home/u/creds.json")
    monkeypatch.setenv("MY_OPT_IN", "ok")
    env = _isolated_env(["MY_OPT_IN"])
    assert "DATABASE_URL" not in env and "GOOGLE_APPLICATION_CREDENTIALS" not in env
    assert env["MY_OPT_IN"] == "ok" and "PATH" in env


def test_isolated_tool_that_prints_does_not_corrupt_its_result(tmp_path):
    from chatty_tools import chatty

    guard = Guard(PolicyEngine(POLICY), Ledger(tmp_path / "l.jsonl"))
    wrapped = guard.guarded_tool("read_private", categories=["data_access"], isolate=True)(chatty)
    assert wrapped(guard.session("A"), 4) == 8


def test_isolated_result_cannot_be_forged_by_tool_output(tmp_path):
    from chatty_tools import forger

    guard = Guard(PolicyEngine(POLICY), Ledger(tmp_path / "l.jsonl"))
    wrapped = guard.guarded_tool("read_private", categories=["data_access"], isolate=True)(forger)
    assert wrapped(guard.session("A")) == "real"


def test_isolated_call_records_a_result_digest(tmp_path):
    from chatty_tools import chatty

    guard = Guard(PolicyEngine(POLICY), Ledger(tmp_path / "l.jsonl"))
    guard.guarded_tool("read_private", categories=["data_access"], isolate=True)(chatty)(guard.session("A"), 1)
    rec = next(iter(guard.ledger))
    assert rec["decision"] == "sandboxed" and rec["result_digest"]


def test_function_defined_in_a_script_run_directly_can_be_isolated(tmp_path):
    script = tmp_path / "run_it.py"
    script.write_text(textwrap.dedent(f"""
        from auditrail import Guard, Ledger, PolicyEngine
        def triple(x):
            return x * 3
        if __name__ == "__main__":
            g = Guard(PolicyEngine({{"version":"v","agents":{{"A":{{"allowed_tools":["t"],"tool_categories":{{"t":[]}}}}}}}}),
                      Ledger(r"{tmp_path / 'l.jsonl'}"))
            print("RESULT", g.guarded_tool("t", isolate=True)(triple)(g.session("A"), 7))
    """), encoding="utf-8")
    import subprocess
    out = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, encoding="utf-8",
                         env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
    assert "RESULT 21" in out.stdout, out.stderr


def test_error_reason_is_a_digest_by_default_and_argument_text_never_lands_in_the_ledger(tmp_path):
    guard = Guard(PolicyEngine(POLICY), Ledger(tmp_path / "l.jsonl"))

    def leaky(card):
        raise ValueError(f"cannot charge card {card}")

    tool = guard.guarded_tool("read_private", categories=["data_access"])(leaky)
    with pytest.raises(ValueError):
        tool(guard.session("A"), "4111-1111-1111-1111")
    assert "4111" not in (tmp_path / "l.jsonl").read_text(encoding="utf-8")
