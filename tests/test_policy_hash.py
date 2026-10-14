"""The full policy hash is bound into every call record.

Why: a version string such as "policy-v1" can stay the same after the rules change, so
"which rules were in force when this call was allowed?" would have no answer. The hash
of the whole policy cannot be reused for different rules.
"""
import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from auditrail import Guard, Ledger, PolicyEngine, RecorderService, RemoteLedger, Signer, ToolDenied
from auditrail.ledger import GENESIS_HASH, InvalidRecord, _canonical, record_hash
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")

POLICY = {
    "version": "policy-v1",
    "agents": {"a": {"allowed_tools": ["read", "web", "send"],
                     "tool_categories": {"read": ["data_access"], "web": ["untrusted_input"], "send": ["external_comm"]}}},
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}


def _guard(tmp_path, policy=POLICY, name="l.jsonl", signer=None):
    return Guard(PolicyEngine(policy), Ledger(tmp_path / name, signer=signer, fsync=False))


def test_every_decision_carries_the_policy_hash(tmp_path):
    g = _guard(tmp_path)
    read = g.guarded_tool("read", categories=["data_access"])(lambda: 1)
    web = g.guarded_tool("web", categories=["untrusted_input"])(lambda: 1)
    send = g.guarded_tool("send", categories=["external_comm"])(lambda: 1)
    boom = g.guarded_tool("read", categories=["data_access"])(lambda: 1 / 0)
    s = g.session("a")
    read(s)
    web(s)
    with pytest.raises(ToolDenied):
        send(s)  # a deny
    with pytest.raises(ZeroDivisionError):
        boom(g.session("a"))  # an error
    calls = [r for r in g.ledger if r["kind"] == "call"]
    assert {r["decision"] for r in calls} == {"allow", "deny", "error"}
    assert all(r["policy_hash"] == g.policy.policy_hash for r in calls)
    assert all(r["policy_version"] == "policy-v1" for r in calls)


def test_same_version_string_but_changed_rules_is_visible_in_the_evidence(tmp_path):
    changed = copy.deepcopy(POLICY)
    changed["agents"]["a"]["allowed_tools"].append("delete_everything")  # same "policy-v1" label, different rules
    path = tmp_path / "shared.jsonl"
    signer = Signer.generate()
    for policy in (POLICY, changed):
        g = Guard(PolicyEngine(policy), Ledger(path, signer=signer, fsync=False))
        g.guarded_tool("read", categories=["data_access"])(lambda: 1)(g.session("a"))
    hashes = [r["policy_hash"] for r in Ledger(path)]
    assert len(set(hashes)) == 2 and {r["policy_version"] for r in Ledger(path)} == {"policy-v1"}

    res = verify_all(path, public_keys={signer.key_id: signer.public_hex})
    assert res["status"] == "OK"
    assert [(p["first_seq"], p["last_seq"]) for p in res["policy_hashes"]] == [(0, 0), (1, 1)]
    assert any("policy changed" in n for n in res["notes"])


def test_the_hash_is_a_function_of_the_rules_not_of_key_order_or_whitespace():
    shuffled = json.loads(json.dumps(POLICY, sort_keys=True))
    assert PolicyEngine(shuffled).policy_hash == PolicyEngine(POLICY).policy_hash


def test_recorder_path_keeps_the_hash(tmp_path):
    key = Signer.generate()
    svc = RecorderService(Ledger(tmp_path / "r.jsonl", signer=key), heartbeat_s=0).start()
    try:
        g = Guard(PolicyEngine(POLICY), RemoteLedger(port=svc.address[1]))
        g.guarded_tool("read", categories=["data_access"])(lambda: 1)(g.session("a"))
    finally:
        svc.stop()
    call = next(r for r in Ledger(tmp_path / "r.jsonl") if r["kind"] == "call")
    assert call["policy_hash"] == g.policy.policy_hash
    beat = next(r for r in Ledger(tmp_path / "r.jsonl") if r["kind"] == "heartbeat")
    assert beat["policy_hash"] is None  # a recorder started without a policy says "unknown", not ""
    assert verify_all(tmp_path / "r.jsonl", public_keys={key.key_id: key.public_hex})["status"] == "OK"


@pytest.mark.parametrize("bad", ["policy-v1", "", "A" * 64, "a" * 63, "a" * 65, " " + "a" * 63, 5, True, ["a" * 64]])
def test_the_writer_refuses_a_value_that_is_not_a_hash(tmp_path, bad):
    led = Ledger(tmp_path / "w.jsonl")
    with pytest.raises(InvalidRecord):
        led.record(agent_id="a", session_id="s", policy_version="v", policy_hash=bad, tool="t", categories=[], args={},
                   decision="allow")


@pytest.mark.parametrize("bad", ["policy-v1", "", "A" * 64, "a" * 63, 5, True, ["a" * 64], {"x": 1}])
def test_both_verifiers_reject_a_forged_non_hash_even_when_it_is_correctly_hashed(tmp_path, bad):
    g = _guard(tmp_path)
    g.guarded_tool("read", categories=["data_access"])(lambda: 1)(g.session("a"))
    recs = [json.loads(x) for x in (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    recs[0]["policy_hash"] = bad
    prev = GENESIS_HASH
    for r in recs:
        r["prev_hash"] = prev
        r["hash"] = record_hash(prev, r)
        prev = r["hash"]
    forged = tmp_path / "forged.jsonl"
    forged.write_text("".join(_canonical(r) + "\n" for r in recs), encoding="utf-8")
    assert verify_all(forged)["status"] == "MALFORMED_RECORD"
    if BINARY is not None:
        out = subprocess.run([str(BINARY), str(forged), "--json"], capture_output=True, text=True, encoding="utf-8")
        assert json.loads(out.stdout)["status"] == "MALFORMED_RECORD"


LEGACY = ROOT / "tests" / "fixtures" / "legacy_v01_ledger.jsonl"  # written by the real v0.1 code


def test_a_genuine_v01_ledger_is_not_called_tampered(tmp_path):
    """v0.1 stored duration_ms as a float; the v2 reading rules forbid floats. That must not
    turn innocent old evidence into a tamper alarm."""
    assert b'"format"' not in LEGACY.read_bytes() and b'"duration_ms":0.0' in LEGACY.read_bytes()
    res = verify_all(LEGACY)
    assert res["status"] == "LEGACY_FORMAT" and "--legacy-v01" in res["detail"]
    if BINARY is not None:
        out = subprocess.run([str(BINARY), str(LEGACY), "--json"], capture_output=True, text=True, encoding="utf-8")
        assert json.loads(out.stdout)["status"] == "LEGACY_FORMAT"


def test_legacy_option_checks_the_old_hash_chain_and_says_how_weak_that_is(tmp_path):
    from auditrail.verifier import verify_legacy_v01

    res = verify_legacy_v01(LEGACY)
    assert res["status"] == "OK" and res["legacy"] is True and any("unsigned" in n for n in res["notes"])
    edited = tmp_path / "edited.jsonl"
    edited.write_bytes(LEGACY.read_bytes().replace(b'"decision":"deny"', b'"decision":"allow"'))
    bad = verify_legacy_v01(edited)
    assert bad["status"] == "TAMPERED_LEDGER" and bad["bad_seq"] == 2


def test_cli_legacy_flag(tmp_path, capsys):
    from auditrail.cli import main

    assert main(["verify", str(LEGACY)]) == 1
    assert "LEGACY_FORMAT" in capsys.readouterr().out
    assert main(["verify", str(LEGACY), "--legacy-v01"]) == 0
    assert "legacy v0.1" in capsys.readouterr().out
