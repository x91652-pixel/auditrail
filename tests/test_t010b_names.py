"""T-010b, D-9 (category names must be known, or declared) and the D-8 confirmations.

D-8 (kept strictest):
  1. `internal` together with any other category, custom ones included, is an error
     (the built-in combinations: tests/test_t006_labels.py::test_d3_internal_plus_any_other_category_in_the_policy_is_refused_at_load)
  2. (recorder: loose ledger/anchors are refused too -- see test_t010b_recorder.py)
  3. the same tool labelled differently in different agent sections is an error when it is wrapped
"""
import warnings

import pytest

from auditrail import Guard, Ledger, PolicyEngine
from auditrail.policy import BUILTIN_CATEGORIES, PolicyError, UnclassifiedToolWarning


_UNSET = object()


def cfg(tool_categories, custom=_UNSET, **top):
    c = {"version": "t10b", "agents": {"a": {"allowed_tools": ["t"], "tool_categories": tool_categories}}}
    if custom is not _UNSET:
        c["custom_categories"] = custom
    c.update(top)
    return c


def guard_for(config, tmp_path):
    return Guard(PolicyEngine(config), Ledger(tmp_path / "l.jsonl", fsync=False))


# ------------------------------------------------------------------ D-9: the known set

def test_builtin_set_is_exactly_what_the_code_defines():
    assert BUILTIN_CATEGORIES == {"data_access", "untrusted_input", "external_comm", "state_change", "internal",
                                  "agent_to_agent"}


@pytest.mark.parametrize("written, suggestion", [
    ("State_Change", "state_change"),
    ("STATE_CHANGE", "state_change"),
    ("INTERNAL", "internal"),
    (" internal", "internal"),
    ("internal ", "internal"),
    ("state-change", "state_change"),
    ("state change", "state_change"),
    ("Data_Access", "data_access"),
    ("data_acess", "data_access"),
    ("external-comm", "external_comm"),
    ("untrusted_inputs", "untrusted_input"),
])
def test_d9_non_canonical_or_misspelled_names_are_refused_with_a_suggestion(written, suggestion):
    with pytest.raises(PolicyError) as exc:
        PolicyEngine(cfg({"t": [written]}))
    msg = str(exc.value)
    assert repr(written) in msg and "'t'" in msg and "agent 'a'" in msg
    assert f"did you mean '{suggestion}'?" in msg, msg


def test_d9_a_name_with_no_close_match_points_at_the_declaration_syntax():
    with pytest.raises(PolicyError) as exc:
        PolicyEngine(cfg({"t": ["quantum_flux"]}))
    msg = str(exc.value)
    assert "unknown category 'quantum_flux'" in msg and "custom_categories" in msg
    assert "did you mean" not in msg


def test_d9_it_is_the_same_error_without_strict_mode():
    with pytest.raises(PolicyError):
        PolicyEngine(cfg({"t": ["State_Change"]}), strict=False)
    with pytest.raises(PolicyError):
        PolicyEngine(cfg({"t": ["State_Change"]}), strict=True)


def test_d9_a_declared_custom_category_is_accepted_and_changes_the_policy_hash():
    plain = PolicyEngine(cfg({"t": ["data_access"]}))
    engine = PolicyEngine(cfg({"t": ["data_access", "team_billing"]}, custom=["team_billing"]))
    assert engine.categories_for("a", "t") == ["data_access", "team_billing"]
    assert engine.known_categories == BUILTIN_CATEGORIES | {"team_billing"}
    assert plain.known_categories == BUILTIN_CATEGORIES, "no declaration means built-ins only"
    assert engine.policy_hash != PolicyEngine(cfg({"t": ["data_access"]}, custom=["team_billing"])).policy_hash


def test_d9_a_suggestion_can_be_a_declared_custom_name():
    with pytest.raises(PolicyError, match="did you mean 'team_billing'"):
        PolicyEngine(cfg({"t": ["Team_Billing"]}, custom=["team_billing"]))


@pytest.mark.parametrize("bad", ["Team_X", "team x", "team-x", " team_x", "", "9lives", "x" * 70])
def test_d9_custom_names_must_be_written_in_the_canonical_form(bad):
    with pytest.raises(PolicyError, match="custom_categories"):
        PolicyEngine(cfg({"t": ["data_access"]}, custom=[bad]))


@pytest.mark.parametrize("bad", ["team_x", None, 5, [["a"]], {"a": 1}])
def test_d9_custom_categories_must_be_a_list_of_strings(bad):
    with pytest.raises(PolicyError, match="custom_categories"):
        PolicyEngine(cfg({"t": ["data_access"]}, custom=bad))


def test_d9_redeclaring_a_builtin_is_refused_to_keep_the_set_unambiguous():
    with pytest.raises(PolicyError, match="already built in"):
        PolicyEngine(cfg({"t": ["data_access"]}, custom=["data_access"]))


def test_d9_the_default_section_is_checked_as_well():
    config = {"version": "t10b", "default": {"allowed_tools": ["t"], "tool_categories": {"t": ["Internal"]}}}
    with pytest.raises(PolicyError, match="default"):
        PolicyEngine(config)


def test_d9_call_site_labels_get_the_same_check(tmp_path):
    guard = guard_for(cfg({"t": ["data_access"]}), tmp_path)
    with pytest.raises(PolicyError, match="did you mean 'state_change'"):
        guard.guarded_tool("t", categories=["State_Change"])
    with pytest.raises(PolicyError, match="unknown category 'team_x'"):
        guard.guarded_tool("t", categories=["team_x"])
    with pytest.raises(PolicyError, match="did you mean 'internal'"):
        guard.guarded_tool("t", categories=[" internal"])
    declared = guard_for(cfg({"t": ["data_access"]}, custom=["team_x"]), tmp_path)
    assert declared.guarded_tool("t", categories=["team_x"])(lambda *a: 1)


def test_d9_categories_that_arrive_with_a_signed_message_are_not_policed_by_name(tmp_path):
    """A sender's workflow categories are data from another policy; they are counted, not validated."""
    guard = guard_for(cfg({"t": ["data_access"]}), tmp_path)
    s = guard.session("a", inherited=["peer_only_category"])
    assert "peer_only_category" in guard.policy.seen(s)


def test_d9_a_policy_written_in_canonical_names_still_loads_unchanged():
    engine = PolicyEngine(cfg({"t": ["data_access", "external_comm"], "u": ["internal"], "v": []}))
    assert engine.categories_for("a", "t") == ["data_access", "external_comm"]


# ------------------------------------------------------------------ D-8 confirmations

def test_d8_1_internal_with_a_declared_custom_category_is_an_error():
    with pytest.raises(PolicyError) as exc:
        PolicyEngine(cfg({"t": ["internal", "team_billing"]}, custom=["team_billing"]))
    assert "'t'" in str(exc.value) and "internal" in str(exc.value) and "team_billing" in str(exc.value)


def two_agents(a_cats, b_cats):
    return {"version": "t10b", "agents": {
        "a": {"allowed_tools": ["t"], "tool_categories": {"t": a_cats}},
        "b": {"allowed_tools": ["t"], "tool_categories": {"t": b_cats}}}}


def test_d8_3_the_same_tool_labelled_differently_in_two_agent_sections_fails_when_wrapped(tmp_path):
    guard = guard_for(two_agents(["data_access"], ["external_comm"]), tmp_path)  # loading is fine
    with pytest.raises(PolicyError) as exc:
        guard.guarded_tool("t")
    msg = str(exc.value)
    assert "'t'" in msg and "agent 'a'" in msg and "agent 'b'" in msg and "data_access" in msg and "external_comm" in msg


def test_d8_3_an_empty_label_in_one_section_and_a_label_in_another_is_a_difference_too(tmp_path):
    guard = guard_for(two_agents([], ["data_access"]), tmp_path)
    with pytest.raises(PolicyError, match="agent 'a'.*agent 'b'|agent 'b'.*agent 'a'"):
        guard.guarded_tool("t")


def test_d8_3_identical_labels_and_a_tool_listed_by_one_agent_only_are_fine(tmp_path):
    guard = guard_for(two_agents(["data_access"], ["data_access"]), tmp_path)
    assert guard.guarded_tool("t")(lambda *a: 1)
    one = {"version": "t10b", "agents": {"a": {"allowed_tools": ["t"], "tool_categories": {"t": ["data_access"]}},
                                         "b": {"allowed_tools": ["u"], "tool_categories": {"u": ["external_comm"]}}}}
    assert guard_for(one, tmp_path).guarded_tool("t")(lambda *a: 1)


def test_d8_3_order_of_the_labels_does_not_matter(tmp_path):
    guard = guard_for(two_agents(["data_access", "external_comm"], ["external_comm", "data_access"]), tmp_path)
    with warnings.catch_warnings():
        warnings.simplefilter("error", UnclassifiedToolWarning)
        assert guard.guarded_tool("t")(lambda *a: 1)
