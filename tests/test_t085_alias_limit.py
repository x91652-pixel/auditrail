"""T-085 G1: YAML alias expansion is bounded before the policy is hashed or built."""
import argparse
import hashlib
import json
import time

import pytest

from auditrail import Signer, recorder
from auditrail.cli import main
from auditrail import policy
from auditrail.policy import PolicyEngine, PolicyError

MAX_POLICY_NODES = getattr(policy, "MAX_POLICY_NODES", 100_000)

VALID = """
version: "v1"
agents:
  bot:
    allowed_tools: [t]
    tool_categories:
      t: []
"""


def bomb(levels: int, fanout: int = 10) -> str:
    """A few hundred bytes that expand to fanout**levels leaf nodes (levels=6 -> 10**6, far over the limit)."""
    lines = ['version: "v1"', "x0: &a0 [" + ", ".join(["lol"] * fanout) + "]"]
    for i in range(1, levels):
        lines.append(f"x{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * fanout) + "]")
    lines.append("agents: {}")
    return "\n".join(lines) + "\n"


def test_engine_refuses_a_shallow_bomb_quickly(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(bomb(6), encoding="utf-8")
    assert len(p.read_text()) < 2000
    t0 = time.monotonic()
    with pytest.raises(PolicyError, match=str(MAX_POLICY_NODES)):
        PolicyEngine.from_yaml(str(p))
    assert time.monotonic() - t0 < 5


def test_lint_refuses_the_bomb_with_exit_1(tmp_path, capsys):
    p = tmp_path / "p.yaml"
    p.write_text(bomb(6), encoding="utf-8")
    t0 = time.monotonic()
    code = main(["lint", str(p)])
    assert time.monotonic() - t0 < 5
    out = capsys.readouterr().out
    assert code == 1 and "[INVALID]" in out and str(MAX_POLICY_NODES) in out


def test_recorder_policy_refuses_the_bomb_before_starting(tmp_path, monkeypatch):
    monkeypatch.setenv("T085_TOKEN", "t")
    key, _ = Signer.generate().save(tmp_path / "rec")
    p = tmp_path / "p.yaml"
    p.write_text(bomb(6), encoding="utf-8")
    ns = argparse.Namespace(
        key=str(key), ledger=str(tmp_path / "l.jsonl"), port=0, policy=str(p), heartbeat=0, anchors=None,
        anchor_every=None, witness_file=None, git_repo=None, token_env="T085_TOKEN", allow_loose_permissions=True)
    t0 = time.monotonic()
    with pytest.raises(PolicyError):
        recorder.serve(ns)
    assert time.monotonic() - t0 < 5


def test_a_bomb_just_under_the_limit_is_accepted_and_one_over_is_not(tmp_path):
    ok = tmp_path / "ok.yaml"
    ok.write_text(bomb(4), encoding="utf-8")  # 10**4 leaves: well under
    PolicyEngine.from_yaml(str(ok))
    big = tmp_path / "big.yaml"
    big.write_text(bomb(5, fanout=11), encoding="utf-8")  # 11**5 = 161051 leaves
    with pytest.raises(PolicyError):
        PolicyEngine.from_yaml(str(big))


def test_recursive_alias_is_refused(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text('version: "v1"\nloop: &a [*a]\n', encoding="utf-8")
    with pytest.raises(PolicyError):
        PolicyEngine.from_yaml(str(p))


def test_a_legitimate_policy_keeps_its_hash(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(VALID, encoding="utf-8")
    engine = PolicyEngine.from_yaml(str(p))
    expected = hashlib.sha256(json.dumps(
        {"version": "v1", "agents": {"bot": {"allowed_tools": ["t"], "tool_categories": {"t": []}}}},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    assert engine.policy_hash == expected


def test_aliases_in_a_small_policy_still_work(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text('version: "v1"\nagents:\n  a: &s {allowed_tools: [t], tool_categories: {t: []}}\n  b: *s\n',
                 encoding="utf-8")
    assert set(PolicyEngine.from_yaml(str(p)).agents) == {"a", "b"}
