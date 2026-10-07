"""Edge cases and failure paths across the core modules."""
import json
import time

import pytest

from auditrail import Guard, Ledger, PolicyEngine, SessionState, ToolDenied
from auditrail.agent_bridge import ReplayGuard, SignatureError, sign_message, verify_message
from auditrail.agent_bridge import _mac
from auditrail.cli import main
from fixtures_tools import add, fail_always, never_runs

POLICY = {
    "version": "edge-v1",
    "agents": {
        "a": {
            "allowed_tools": ["read", "web", "send", "boom", "add_iso"],
            "tool_categories": {"read": ["data_access"], "web": ["untrusted_input"],
                                "send": ["external_comm"], "boom": [], "add_iso": []},
            "enforce_lethal_trifecta": True,
            "trifecta_exempt_tools": [],
        },
        "b": {
            "allowed_tools": ["send"],
            "tool_categories": {"send": ["external_comm"]},
            "enforce_lethal_trifecta": True,
        },
    },
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}


@pytest.fixture
def guard(tmp_path):
    return Guard(PolicyEngine(POLICY), Ledger(tmp_path / "l.jsonl"))


# ----------------------------------------------------------------- ledger

def test_empty_ledger_verifies(tmp_path):
    assert Ledger(tmp_path / "empty.jsonl").verify() == (True, None)


def test_inserted_record_is_detected(tmp_path):
    path = tmp_path / "l.jsonl"
    led = Ledger(path)
    for i in range(3):
        led.record(agent_id="a", session_id="s", policy_version="v", tool=f"t{i}",
                   categories=[], args={}, decision="allow", result={})
    lines = path.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[1])
    forged["tool"] = "forged"
    lines.insert(2, json.dumps(forged, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad = Ledger(path).verify()
    assert ok is False and bad is not None


def test_reordered_records_are_detected(tmp_path):
    path = tmp_path / "l.jsonl"
    led = Ledger(path)
    for i in range(3):
        led.record(agent_id="a", session_id="s", policy_version="v", tool=f"t{i}",
                   categories=[], args={}, decision="allow", result={})
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert Ledger(path).verify()[0] is False


def test_unicode_arguments_round_trip_and_verify(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    led.record(agent_id="a", session_id="s", policy_version="v", tool="t",
               categories=[], args={"姓名": "林小姐", "地址": "台中市西屯區"}, decision="allow", result={"ok": "✓"})
    assert led.verify() == (True, None)


def test_error_decision_is_accepted_by_the_ledger(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    rec = led.record(agent_id="a", session_id="s", policy_version="v", tool="t",
                     categories=[], args={}, decision="error", reason="ValueError: x")
    assert rec.decision == "error"
    assert led.verify() == (True, None)


def test_invalid_decision_value_is_rejected(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    with pytest.raises(AssertionError):
        led.record(agent_id="a", session_id="s", policy_version="v", tool="t",
                   categories=[], args={}, decision="maybe")


# ----------------------------------------------------------------- policy

def test_categories_accumulate_across_different_tools_in_one_session():
    eng = PolicyEngine(POLICY)
    s = SessionState(session_id="x", agent_id="a")
    for tool in ("read", "web"):
        assert eng.check(s, tool).allow
        eng.commit(s, tool)
    assert s.categories_seen == {"data_access", "untrusted_input"}
    assert eng.check(s, "send").allow is False


def test_sessions_do_not_share_trifecta_state():
    eng = PolicyEngine(POLICY)
    s1 = SessionState(session_id="1", agent_id="a")
    s2 = SessionState(session_id="2", agent_id="a")
    for tool in ("read", "web"):
        eng.commit(s1, tool)
    assert eng.check(s2, "send").allow is True


def test_agent_without_a_trifecta_rule_can_do_all_three(tmp_path):
    cfg = json.loads(json.dumps(POLICY))
    cfg["agents"]["a"]["enforce_lethal_trifecta"] = False
    eng = PolicyEngine(cfg)
    s = SessionState(session_id="x", agent_id="a")
    for tool in ("read", "web"):
        eng.commit(s, tool)
    assert eng.check(s, "send").allow is True


def test_policy_version_is_recorded_on_every_decision(guard):
    s = guard.session("a")

    @guard.guarded_tool("boom")
    def boom():
        return 1

    boom(s)
    assert next(iter(guard.ledger))["policy_version"] == "edge-v1"


# ----------------------------------------------------------------- sandbox failures

def test_exception_in_a_tool_is_logged_as_error_and_reraised(guard):
    @guard.guarded_tool("boom")
    def boom():
        raise ValueError("kaboom")

    s = guard.session("a")
    with pytest.raises(ValueError):
        boom(s)
    rec = next(iter(guard.ledger))
    assert rec["decision"] == "error"
    # exception messages often echo raw arguments, so by default only the type + a digest is kept
    assert rec["reason"].startswith("ValueError")
    assert "kaboom" not in rec["reason"]


def test_error_text_is_recorded_only_when_opted_in(tmp_path):
    guard = Guard(PolicyEngine(POLICY), Ledger(tmp_path / "l.jsonl"), record_error_text=True)

    @guard.guarded_tool("boom")
    def boom():
        raise ValueError("kaboom")

    with pytest.raises(ValueError):
        boom(guard.session("a"))
    assert "kaboom" in next(iter(guard.ledger))["reason"]


def test_failed_call_still_counts_toward_trifecta_state(guard):
    @guard.guarded_tool("read")
    def read():
        raise RuntimeError("half-read")

    s = guard.session("a")
    with pytest.raises(RuntimeError):
        read(s)
    assert s.categories_seen == {"data_access"}


def test_isolated_tool_returns_real_result(guard):
    iso = guard.guarded_tool("add_iso", isolate=True, timeout=10)(add)
    assert iso(guard.session("a"), 40, 2) == 42


def test_isolated_tool_with_non_json_args_is_rejected_clearly(guard):
    iso = guard.guarded_tool("add_iso", isolate=True, timeout=10)(add)
    with pytest.raises(TypeError, match="JSON-serializable"):
        iso(guard.session("a"), object(), 2)


def test_isolated_tool_exception_is_surfaced_and_logged(guard):
    iso = guard.guarded_tool("add_iso", isolate=True, timeout=10)(fail_always)
    with pytest.raises(RuntimeError, match="nope"):
        iso(guard.session("a"), 1)
    assert next(iter(guard.ledger))["decision"] == "error"


def test_denied_call_is_never_executed_even_with_isolation(guard):
    wrapped = guard.guarded_tool("notallowed", isolate=True)(never_runs)
    with pytest.raises(ToolDenied):
        wrapped(guard.session("a"))
    assert next(iter(guard.ledger))["decision"] == "deny"


# ----------------------------------------------------------------- agent bridge

def test_message_from_the_future_is_rejected():
    msg = sign_message("a", {"x": 1}, "s")
    msg.ts = time.time() + 3600
    msg.sig = _mac("s", msg.sender, msg.ts, msg.nonce, msg.payload)
    with pytest.raises(SignatureError, match="replay"):
        verify_message(msg, "s")


def test_non_dict_payloads_round_trip():
    for payload in ([1, 2, 3], "text", 42, None):
        msg = sign_message("a", payload, "s")
        assert verify_message(msg, "s") == payload


def test_replay_guard_only_blocks_the_same_nonce():
    rg = ReplayGuard()
    m1 = sign_message("a", {"n": 1}, "s")
    m2 = sign_message("a", {"n": 2}, "s")
    verify_message(m1, "s", replay_guard=rg)
    verify_message(m2, "s", replay_guard=rg)  # different nonce, fine


# ----------------------------------------------------------------- cli

def test_verify_missing_file_is_an_error_not_a_silent_pass(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.jsonl"
    code = main(["verify", str(missing)])
    assert code == 2
    assert not missing.exists()  # verify must not create the file as a side effect
    assert "not found" in capsys.readouterr().out


def test_verify_reports_tamper_with_nonzero_exit(tmp_path, capsys):
    path = tmp_path / "l.jsonl"
    led = Ledger(path)
    led.record(agent_id="a", session_id="s", policy_version="v", tool="t",
               categories=[], args={}, decision="allow", result={})
    path.write_text(path.read_text(encoding="utf-8").replace('"allow"', '"deny"'), encoding="utf-8")
    assert main(["verify", str(path)]) == 1
