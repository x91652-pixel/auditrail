"""C-1 (type part): a policy whose label fields are not lists of strings is refused when it is
loaded, naming the tool and the section -- never a TypeError/AttributeError at call time and never
a string silently expanded into a set of characters."""
import pytest

from auditrail import Guard, Ledger, PolicyEngine
from auditrail.policy import PolicyError


def policy(tool_categories, **agent):
    return {"version": "t10", "agents": {"a": {"allowed_tools": ["t"], "tool_categories": tool_categories, **agent}}}


@pytest.mark.parametrize("value", ["state_change", "internal", None, 5, [["x"]], [None], [5], {"x": 1}, True],
                         ids=lambda v: repr(v))
def test_tool_category_values_must_be_a_list_of_strings(value):
    with pytest.raises(PolicyError) as exc:
        PolicyEngine(policy({"t": value}))
    msg = str(exc.value)
    assert "'t'" in msg and "agent 'a'" in msg, msg
    assert "list of strings" in msg


def test_a_string_is_never_expanded_into_characters():
    """The old behaviour: set("state_change") -> {'s','t','a',...}; the rule never fired and nothing complained."""
    with pytest.raises(PolicyError, match="state_change"):
        PolicyEngine(policy({"t": "state_change"}, enforce_state_change_after_untrusted=True))


def test_an_agent_section_that_is_null_or_not_a_mapping_is_refused_at_load():
    with pytest.raises(PolicyError, match="agent 'a'"):
        PolicyEngine({"version": "t10", "agents": {"a": None}})
    with pytest.raises(PolicyError, match="agent 'a'"):
        PolicyEngine({"version": "t10", "agents": {"a": ["t"]}})


def test_the_default_section_and_other_shapes_are_checked_too():
    with pytest.raises(PolicyError, match="default"):
        PolicyEngine({"version": "t10", "default": None})
    with pytest.raises(PolicyError, match="'agents' must be a mapping"):
        PolicyEngine({"version": "t10", "agents": ["a"]})
    with pytest.raises(PolicyError, match="tool_categories"):
        PolicyEngine({"version": "t10", "agents": {"a": {"allowed_tools": [], "tool_categories": ["t"]}}})
    with pytest.raises(PolicyError, match="mapping"):
        PolicyEngine(None)
    with pytest.raises(PolicyError, match="mapping"):
        PolicyEngine(["version"])


@pytest.mark.parametrize("field", ["allowed_tools", "trifecta_exempt_tools", "state_change_allowed_tools"])
def test_tool_name_lists_must_be_lists_of_strings_as_well(field):
    for bad in ("read_db", None, 5, [1]):
        with pytest.raises(PolicyError, match=field):
            PolicyEngine({"version": "t10", "agents": {"a": {"allowed_tools": [], field: bad}}})


def test_valid_shapes_still_load_and_tuples_are_accepted():
    engine = PolicyEngine(policy({"t": ["data_access", "external_comm"], "u": ("internal",), "v": []},
                                 trifecta_exempt_tools=["t"]))
    assert engine.categories_for("a", "t") == ["data_access", "external_comm"]


def test_an_empty_yaml_file_is_a_policy_error_not_a_type_error(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    with pytest.raises(PolicyError):
        PolicyEngine.from_yaml(str(p))


# ------------------------------------------------------------ call site

@pytest.fixture
def guard(tmp_path):
    return Guard(PolicyEngine(policy({"t": ["data_access"]})), Ledger(tmp_path / "l.jsonl", fsync=False))


@pytest.mark.parametrize("value", ["state_change", [["x"]], [None], [5], None, 5, {"state_change": 1}],
                         ids=lambda v: repr(v))
def test_call_site_categories_must_be_strings_in_a_list(guard, value):
    with pytest.raises(PolicyError) as exc:
        guard.guarded_tool("t", categories=value)
    assert "'t'" in str(exc.value) and "call site" in str(exc.value)


def test_call_site_accepts_list_tuple_and_set_of_strings(guard):
    for ok in (["data_access"], ("data_access",), {"data_access"}, ()):
        assert guard.guarded_tool("t", categories=ok)(lambda *a: 1)
