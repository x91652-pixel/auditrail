"""Limits that SECURITY.md states, pinned so that fixing one is a visible, deliberate change.

These assert the *current* behaviour. If one of them starts failing because the limit was removed, update
SECURITY.md ("Where the tests do not reach" / "What remains") in the same commit.
"""
import yaml

from auditrail import PolicyEngine
from auditrail.policy import PolicyError  # noqa: F401  (documented: not raised in these cases)


def test_a_duplicate_yaml_key_is_not_reported_the_last_one_wins(tmp_path):
    text = ("version: lim\nagents:\n  a:\n    allowed_tools: [t]\n"
            "    tool_categories: {t: [state_change]}\n"
            "    tool_categories: {t: [data_access]}\n")
    p = tmp_path / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    engine = PolicyEngine.from_yaml(str(p))  # no error
    assert engine.categories_for("a", "t") == ["data_access"], "the later key silently replaced the earlier one"
    assert yaml.safe_load("k: 1\nk: 2\n") == {"k": 2}


def test_policyengine_check_alone_does_not_compare_sections():
    """Cross-section consistency is enforced when a tool is wrapped (Guard.guarded_tool), not by check()."""
    from auditrail.policy import SessionState

    cfg = {"version": "lim", "agents": {
        "a": {"allowed_tools": ["t"], "tool_categories": {"t": ["state_change"]}},
        "b": {"allowed_tools": ["t"], "tool_categories": {}, "enforce_state_change_after_untrusted": True}}}
    engine = PolicyEngine(cfg)
    s = SessionState(session_id="s", agent_id="b")
    s.categories_seen.add("untrusted_input")
    assert engine.check(s, "t").allow is True  # b never labelled it, so nothing fires
    engine2 = PolicyEngine(cfg)
    try:
        engine2.check_call_site_labels("t", [])
    except PolicyError:
        pass
    else:
        raise AssertionError("the wrap-time check should have refused this policy")
