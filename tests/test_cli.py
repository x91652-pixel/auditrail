import json
from pathlib import Path

from auditrail.cli import main
from auditrail.ledger import Ledger

POLICY_YAML = """
version: "v1"
agents:
  bot:
    allowed_tools: [t]
    tool_categories:
      t: []
    enforce_lethal_trifecta: true
"""


def test_verify_ok(tmp_path, capsys):
    ledger = Ledger(tmp_path / "l.jsonl")
    ledger.record(agent_id="a", session_id="s", policy_version="v1", tool="t", categories=[], args={}, decision="allow", result={})
    code = main(["verify", str(tmp_path / "l.jsonl")])
    out = capsys.readouterr().out
    assert code == 0
    assert "[OK]" in out


def test_verify_tamper(tmp_path, capsys):
    path = tmp_path / "l.jsonl"
    ledger = Ledger(path)
    ledger.record(agent_id="a", session_id="s", policy_version="v1", tool="t", categories=[], args={}, decision="allow", result={})
    rec = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    rec["decision"] = "deny"
    path.write_text(json.dumps(rec, sort_keys=True) + "\n", encoding="utf-8")

    code = main(["verify", str(path)])
    out = capsys.readouterr().out
    assert code == 1
    assert "TAMPER DETECTED" in out


def test_lint_ok(tmp_path, capsys):
    p = tmp_path / "policy.yaml"
    p.write_text(POLICY_YAML, encoding="utf-8")
    code = main(["lint", str(p)])
    out = capsys.readouterr().out
    assert code == 0
    assert "[OK]" in out


def test_lint_invalid(tmp_path, capsys):
    p = tmp_path / "policy.yaml"
    p.write_text("agents: {}\n", encoding="utf-8")  # missing required 'version'
    code = main(["lint", str(p)])
    out = capsys.readouterr().out
    assert code == 1
    assert "[INVALID]" in out
