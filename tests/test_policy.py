import pytest

from auditrail.policy import PolicyEngine, PolicyError, SessionState

CONFIG = {
    "version": "test-v1",
    "agents": {
        "bot": {
            "allowed_tools": ["read_data", "read_untrusted", "send_out", "safe_tool"],
            "tool_categories": {
                "read_data": ["data_access"],
                "read_untrusted": ["untrusted_input"],
                "send_out": ["external_comm"],
                "safe_tool": [],
            },
            "enforce_lethal_trifecta": True,
            "trifecta_exempt_tools": [],
        },
        "exempt-bot": {
            "allowed_tools": ["read_data", "read_untrusted", "send_out"],
            "tool_categories": {
                "read_data": ["data_access"],
                "read_untrusted": ["untrusted_input"],
                "send_out": ["external_comm"],
            },
            "enforce_lethal_trifecta": True,
            "trifecta_exempt_tools": ["send_out"],
        },
    },
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}


def test_missing_version_rejected():
    with pytest.raises(PolicyError):
        PolicyEngine({"agents": {}})


def test_tool_not_allowlisted_denied():
    engine = PolicyEngine(CONFIG)
    session = SessionState(session_id="s", agent_id="bot")
    decision = engine.check(session, "not_a_real_tool")
    assert decision.allow is False
    assert "not allow-listed" in decision.reason


def test_two_of_three_categories_is_fine():
    engine = PolicyEngine(CONFIG)
    session = SessionState(session_id="s", agent_id="bot")
    d1 = engine.check(session, "read_data")
    assert d1.allow
    engine.commit(session, "read_data")
    d2 = engine.check(session, "send_out")
    assert d2.allow


def test_third_category_completes_trifecta_and_is_denied():
    engine = PolicyEngine(CONFIG)
    session = SessionState(session_id="s", agent_id="bot")
    for tool in ("read_data", "read_untrusted"):
        d = engine.check(session, tool)
        assert d.allow
        engine.commit(session, tool)
    d3 = engine.check(session, "send_out")
    assert d3.allow is False
    assert "lethal_trifecta" in d3.reason


def test_denied_call_must_not_be_committed():
    engine = PolicyEngine(CONFIG)
    session = SessionState(session_id="s", agent_id="bot")
    for tool in ("read_data", "read_untrusted"):
        engine.check(session, tool)
        engine.commit(session, tool)
    # send_out is denied -- caller must NOT call commit() for a denied
    # decision. Verify the session state reflects only the two committed calls.
    assert session.categories_seen == {"data_access", "untrusted_input"}


def test_exempt_tool_bypasses_trifecta_block():
    engine = PolicyEngine(CONFIG)
    session = SessionState(session_id="s", agent_id="exempt-bot")
    for tool in ("read_data", "read_untrusted"):
        engine.check(session, tool)
        engine.commit(session, tool)
    d3 = engine.check(session, "send_out")
    assert d3.allow is True


def test_unknown_agent_falls_back_to_default_deny_all():
    engine = PolicyEngine(CONFIG)
    session = SessionState(session_id="s", agent_id="never-declared")
    d = engine.check(session, "read_data")
    assert d.allow is False
