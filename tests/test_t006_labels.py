"""T-006, decisions D-2 and D-3: an empty category list is not a declaration in strict mode (D-2, locked
here); `internal` contradicts every other category and such a policy is refused when loaded (D-3).
"""
import argparse
import os
import queue
import subprocess
import sys
import threading
import warnings
from pathlib import Path

import pytest

from auditrail import Guard, Ledger, PolicyEngine, Signer, ToolDenied
from auditrail import _perms
from auditrail.policy import PolicyError, UnclassifiedToolWarning

ROOT = Path(__file__).resolve().parents[1]


def policy(tool_categories, **agent):
    cfg = {"allowed_tools": list(tool_categories), "tool_categories": tool_categories}
    cfg.update(agent)
    return {"version": "t6", "agents": {"a": cfg}}


# ====================================================================== D-2

def test_d2_empty_list_in_strict_mode_is_refused_and_recorded_as_unclassified(tmp_path):
    """Locks D-2. (test_phase1_defaults.py::test_strict_does_not_accept_an_empty_declaration
    checks the refusal; this one also checks what lands in the evidence.)"""
    engine = PolicyEngine(policy({"pure": []}), strict=True)
    ledger = Ledger(tmp_path / "l.jsonl", fsync=False)
    guard = Guard(engine, ledger)
    ran = []
    fn = guard.guarded_tool("pure", categories=[])(lambda *a: ran.append(1))
    with pytest.raises(ToolDenied) as exc:
        fn(guard.session("a"))
    assert ran == []
    rec = list(ledger)[-1]
    assert rec["decision"] == "deny" and rec["tool"] == "pure"
    assert rec["reason"].startswith("unclassified_tool")
    assert exc.value.reason.startswith("unclassified_tool")


def test_d2_the_same_empty_list_is_still_allowed_without_strict_mode(tmp_path):
    engine = PolicyEngine(policy({"pure": []}))
    guard = Guard(engine, Ledger(tmp_path / "l.jsonl", fsync=False))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UnclassifiedToolWarning)
        fn = guard.guarded_tool("pure", categories=[])(lambda *a: "ran")
    assert fn(guard.session("a")) == "ran"


# ====================================================================== D-3

@pytest.mark.parametrize("risk", ["state_change", "external_comm", "data_access", "untrusted_input", "agent_to_agent"])
def test_d3_internal_plus_any_other_category_in_the_policy_is_refused_at_load(risk):
    with pytest.raises(PolicyError) as exc:
        PolicyEngine(policy({"tool_x": ["internal", risk]}))
    msg = str(exc.value)
    assert "tool_x" in msg and "internal" in msg and risk in msg


def test_d3_the_conflict_is_found_in_the_default_section_too():
    cfg = {"version": "t6", "default": {"allowed_tools": ["t"], "tool_categories": {"t": ["internal", "state_change"]}}}
    with pytest.raises(PolicyError, match="t.*internal.*state_change|internal.*state_change.*t"):
        PolicyEngine(cfg)


def test_d3_internal_alone_and_risk_categories_alone_still_load():
    PolicyEngine(policy({"a": ["internal"], "b": ["state_change"], "c": ["data_access", "external_comm"]}))


def test_d3_conflict_at_the_call_site_is_refused_when_the_tool_is_wrapped(tmp_path):
    guard = Guard(PolicyEngine(policy({"t": []})), Ledger(tmp_path / "l.jsonl", fsync=False))
    with pytest.raises(PolicyError, match="t.*internal.*state_change|internal.*state_change.*t"):
        guard.guarded_tool("t", categories=["internal", "state_change"])


def test_d3_call_site_label_that_contradicts_the_policy_is_refused(tmp_path):
    guard = Guard(PolicyEngine(policy({"t": ["state_change"]})), Ledger(tmp_path / "l.jsonl", fsync=False))
    with pytest.raises(PolicyError) as exc:
        guard.guarded_tool("t", categories=["internal"])  # the policy says it changes state
    assert "t" in str(exc.value) and "internal" in str(exc.value) and "state_change" in str(exc.value)
    guard2 = Guard(PolicyEngine(policy({"u": ["internal"]})), Ledger(tmp_path / "l2.jsonl", fsync=False))
    with pytest.raises(PolicyError):
        guard2.guarded_tool("u", categories=["external_comm"])


def test_d3_an_agreeing_call_site_label_is_fine(tmp_path):
    guard = Guard(PolicyEngine(policy({"t": ["internal"]})), Ledger(tmp_path / "l.jsonl", fsync=False))
    assert guard.guarded_tool("t", categories=["internal"])(lambda *a: 1)
