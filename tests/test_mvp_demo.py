"""The MVP demonstration runs end to end and its tamper step really is caught."""
import json
import subprocess
import sys
from pathlib import Path

from auditrail import Signer
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]


def test_the_one_shot_demo_runs_every_step_and_returns_zero():
    r = subprocess.run([sys.executable, "-m", "examples.mvp_demo.run"], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=300)
    out = r.stdout
    assert r.returncode == 0, out + r.stderr
    assert out.startswith("Demonstration: the agent and the signing key are on the same machine here")
    for step in ("[1]", "[2]", "[3]", "[4]", "[5]", "[6]", "[6b]", "[6c]", "[6d]", "[7]", "[8]"):
        assert f"\n{step} " in out, step
    assert "UNEXPECTED" not in out
    assert "TAMPER DETECTED" in out and "BAD_SIGNATURE" in out and "REWRITTEN" in out
    assert out.rstrip().endswith("MVP demo: every step behaved as expected.")


def test_the_agent_leaves_signed_evidence_with_the_expected_refusals(tmp_path):
    from examples.mvp_demo import agent

    signer = Signer.from_seed(bytes(range(32)))
    signer.save(tmp_path / "k")
    counts = agent.run(tmp_path / "k.key", tmp_path / "l.jsonl", quiet=True)
    assert counts == {"allowed": 4, "refused": 2}
    res = verify_all(tmp_path / "l.jsonl", public_keys={signer.key_id: signer.public_hex}, max_gap_s=3600)
    assert res["status"] == "OK"
    reasons = [json.loads(x).get("reason") or "" for x in (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(r.startswith("lethal_trifecta") for r in reasons)
    assert any(r.startswith("unclassified_tool") for r in reasons)


def test_tamper_is_caught_with_and_without_a_rehash(tmp_path):
    from examples.mvp_demo import agent, tamper

    signer = Signer.from_seed(bytes(range(32)))
    signer.save(tmp_path / "k")
    agent.run(tmp_path / "k.key", tmp_path / "l.jsonl", quiet=True)
    keys = {signer.key_id: signer.public_hex}
    idx = tamper.tamper(tmp_path / "l.jsonl", tmp_path / "t.jsonl")
    res = verify_all(tmp_path / "t.jsonl", public_keys=keys)
    assert res["status"] == "TAMPERED_LEDGER" and res["bad_seq"] == idx
    tamper.tamper(tmp_path / "l.jsonl", tmp_path / "r.jsonl", rehash=True)
    assert verify_all(tmp_path / "r.jsonl")["status"] == "OK", "without keys the re-hashed chain is consistent"
    res = verify_all(tmp_path / "r.jsonl", public_keys=keys)
    assert res["status"] == "BAD_SIGNATURE" and res["bad_seq"] == idx
