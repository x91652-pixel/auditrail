"""T-015 N-3: a tool one agent labels and another allows without a label passed silently.
"""
import argparse
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from auditrail import Guard, Ledger, PolicyEngine, Signer, _perms, recorder
from auditrail.policy import PolicyError

SRC = Path(__file__).resolve().parents[1] / "src" / "auditrail"




# ============================================================ N-3

def policy(a_cats="absent", b_cats="absent", default_cats="absent", b_allows=True, a_allows=True):
    """Agent a and agent b both allow tool 't'; 'absent' means the section does not list it in tool_categories."""
    def section(allows, cats):
        s = {"allowed_tools": ["t"] if allows else [], "tool_categories": {}}
        if cats != "absent":
            s["tool_categories"]["t"] = cats
        return s

    cfg = {"version": "t15", "agents": {"a": section(a_allows, a_cats), "b": section(b_allows, b_cats)}}
    if default_cats != "absent":
        cfg["default"] = {"allowed_tools": [], "tool_categories": {"t": default_cats}}
    return cfg


def wrap(config, tmp_path, strict=False):
    g = Guard(PolicyEngine(config, strict=strict), Ledger(tmp_path / "l.jsonl", fsync=False))
    return g.guarded_tool("t")


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("a, b", [(["state_change"], "absent"), ("absent", ["state_change"])],
                         ids=["a-labels-b-does-not", "b-labels-a-does-not"])
def test_n3_labelled_by_one_agent_and_allowed_unlabelled_by_another_is_an_error(tmp_path, a, b, strict):
    with pytest.raises(PolicyError) as exc:
        wrap(policy(a_cats=a, b_cats=b), tmp_path, strict=strict)
    msg = str(exc.value)
    labeller, silent = ("a", "b") if a != "absent" else ("b", "a")
    assert "'t'" in msg and f"agent '{labeller}'" in msg and f"agent '{silent}'" in msg
    assert "allowed_tools" in msg and "tool_categories" in msg, "the fix must be named"


def test_n3_the_exact_scenario_from_the_review_cannot_wrap(tmp_path):
    config = policy(a_cats=["state_change"], b_cats="absent")
    config["agents"]["b"]["enforce_state_change_after_untrusted"] = True
    config["agents"]["a"]["enforce_state_change_after_untrusted"] = True
    with pytest.raises(PolicyError, match="agent 'a'.*agent 'b'"):
        wrap(config, tmp_path)


def test_n3_a_default_section_label_without_an_agent_label_is_an_error(tmp_path):
    with pytest.raises(PolicyError, match="default.*agent 'a'|agent 'a'.*default"):
        wrap(policy(a_cats="absent", b_cats=["state_change"], default_cats=["state_change"]), tmp_path)


def test_n3_identical_labels_everywhere_pass(tmp_path):
    assert wrap(policy(["state_change"], ["state_change"], default_cats=["state_change"]), tmp_path)


def test_n3_a_single_section_that_mentions_the_tool_passes(tmp_path):
    assert wrap(policy(a_cats=["state_change"], b_cats="absent", b_allows=False), tmp_path)
    assert wrap(policy(a_cats="absent", b_cats="absent", a_allows=False, b_allows=False), tmp_path)


def test_n3_an_empty_label_and_no_label_are_the_same_thing(tmp_path):
    assert wrap(policy(a_cats=[], b_cats="absent"), tmp_path)


def test_n3_the_check_is_the_same_in_strict_and_non_strict(tmp_path):
    ok = policy(["data_access"], ["data_access"])
    assert wrap(ok, tmp_path, strict=False) and wrap(ok, tmp_path, strict=True)


def test_n3_the_shipped_example_policy_and_the_simulation_policies_are_unaffected(tmp_path):
    from examples.logistics_sim import company

    root = Path(__file__).resolve().parents[1]
    for config in (yaml.safe_load((root / "policies" / "example_policy.yaml").read_text(encoding="utf-8")),
                   company.POLICY, company.STRICT_POLICY):
        engine = PolicyEngine(config)
        tools = {t for cfg in config["agents"].values() for t in cfg.get("allowed_tools", [])}
        assert tools
        for name in tools:
            engine.check_call_site_labels(name, [])  # raises PolicyError on any cross-section disagreement
