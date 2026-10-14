"""T-015 N-1: custom_categories names were matched with `$`, which accepts a trailing newline.
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




# ============================================================ N-1

def cfg(custom, tool_cats=None):
    return {"version": "t15", "custom_categories": custom,
            "agents": {"a": {"allowed_tools": ["t"], "tool_categories": {"t": tool_cats or ["data_access"]}}}}


BAD_NAMES = [
    "state_change\n", "internal\n", "team_x\n", "team_x\r", "team_x\r\n", "team_x\x00", "team_x ", "team_x\t",
    "team_x ", "team_x ", "team\nx", "team\x00x", "team x", "\nteam_x", " team_x", "\x00team_x",
]


@pytest.mark.parametrize("name", BAD_NAMES, ids=lambda n: repr(n))
def test_n1_custom_names_with_line_breaks_nuls_or_spaces_are_refused(name):
    with pytest.raises(PolicyError, match="custom_categories"):
        PolicyEngine(cfg([name]))


def test_n1_the_exploit_shape_no_longer_loads():
    """Declaring "state_change\\n" used to make a look-alike category that satisfied the name check
    while the state_change rule (an exact comparison) never saw it."""
    config = cfg(["state_change\n"], ["state_change\n"])
    config["agents"]["a"]["enforce_state_change_after_untrusted"] = True
    with pytest.raises(PolicyError):
        PolicyEngine(config)


def test_n1_a_yaml_block_scalar_brings_a_trailing_newline_and_is_refused(tmp_path):
    text = "version: t15\ncustom_categories:\n  - |\n    team_x\nagents: {}\n"
    assert yaml.safe_load(text)["custom_categories"] == ["team_x\n"], "the premise: '|' keeps the final newline"
    p = tmp_path / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError, match="custom_categories"):
        PolicyEngine.from_yaml(str(p))
    ok = tmp_path / "ok.yaml"
    ok.write_text("version: t15\ncustom_categories:\n  - |-\n    team_x\nagents: {}\n", encoding="utf-8")
    assert "team_x" in PolicyEngine.from_yaml(str(ok)).known_categories


def test_n1_good_names_still_load():
    engine = PolicyEngine(cfg(["team_x", "a1", "x" * 64]))
    assert {"team_x", "a1"} <= engine.known_categories


def test_n1_no_regular_expression_in_src_is_anchored_with_a_bare_dollar():
    """`$` matches before a trailing newline; validation patterns must use fullmatch or \\Z."""
    offenders = []
    for path in SRC.rglob("*.py"):
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"re\.(compile|match|search|fullmatch)\(", line) and re.search(r"[^\\]\$[\"']", line):
                offenders.append(f"{path.name}:{no}: {line.strip()}")
    assert offenders == []
