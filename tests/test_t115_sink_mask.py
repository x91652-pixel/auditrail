"""0.3.4 item 2 (A-F2): an unsigned sink_ref edit must not hide definite findings; Python and Rust must agree."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from auditrail import Ledger, Signer
from auditrail.anchor import anchor_ledger
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")


@pytest.fixture
def world(tmp_path):
    s = Signer.from_seed(bytes([4]) * 32)
    (tmp_path / "k.pub").write_text(s.public_hex + "\n")
    t = [1700000000]
    led = Ledger(tmp_path / "l.jsonl", signer=s, clock=lambda: t[0])
    for i in range(4):
        t[0] += 10
        led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={"i": i},
                   decision="allow")
    t[0] += 10
    led.record_heartbeat(recorder_id="r", tools=["t"], policy_version="v", policy_hash=None, calls_attempted=5,
                         calls_recorded=3, interval_s=60)  # two calls ran without evidence
    t[0] += 10
    led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={}, decision="allow")
    anchor_ledger(led, tmp_path / "anch.jsonl", signer=s)
    line = json.loads((tmp_path / "anch.jsonl").read_text().splitlines()[0])
    edited = dict(line, sink_ref="git:deadbeef")  # not hashed, not signed: anyone can change it
    (tmp_path / "anch_edit.jsonl").write_text(json.dumps(edited, sort_keys=True, separators=(",", ":")) + "\n")
    tampered = dict(line, head_hash="0" * 64)
    (tmp_path / "wit_tampered.jsonl").write_text(json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n")
    return tmp_path, {s.key_id: s.public_hex}


def py(world, **kw):
    d, keys = world
    return verify_all(d / "l.jsonl", public_keys=keys, **kw)["status"]


def rust(world, anchors=None, witness=None, gap=None):
    d, _ = world
    cmd = [str(BINARY), str(d / "l.jsonl"), "--pubkey", str(d / "k.pub"), "--json"]
    if anchors: cmd += ["--anchors", str(d / anchors)]
    if witness: cmd += ["--witness", str(d / witness)]
    if gap is not None: cmd += ["--max-gap", str(gap)]
    return json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)["status"]


def test_edited_sink_ref_does_not_hide_unrecorded_calls(world):
    d, _ = world
    assert py(world, anchors_path=d / "anch_edit.jsonl", max_gap_s=3600) == "UNRECORDED_CALLS"


def test_edited_sink_ref_does_not_hide_a_tampered_witness_copy(world):
    d, _ = world
    assert py(world, anchors_path=d / "anch_edit.jsonl", witness_path=d / "wit_tampered.jsonl") not in (
        "SINK_UNREACHABLE", "OK")


def test_with_nothing_else_wrong_the_unreachable_sink_is_still_reported(tmp_path):
    s = Signer.from_seed(bytes([6]) * 32)
    led = Ledger(tmp_path / "l.jsonl", signer=s)
    led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={}, decision="allow")
    anchor_ledger(led, tmp_path / "anch.jsonl", signer=s)
    line = json.loads((tmp_path / "anch.jsonl").read_text().splitlines()[0])
    (tmp_path / "anch.jsonl").write_text(json.dumps(dict(line, sink_ref="git:deadbeef"), sort_keys=True,
                                                     separators=(",", ":")) + "\n")
    assert verify_all(tmp_path / "l.jsonl", public_keys={s.key_id: s.public_hex},
                      anchors_path=tmp_path / "anch.jsonl")["status"] == "SINK_UNREACHABLE"


@pytest.mark.skipif(BINARY is None, reason="Rust verifier not built")
def test_python_and_rust_agree_on_these_cases(world):
    d, _ = world
    cases = [dict(anchors_path=d / "anch_edit.jsonl", max_gap_s=3600),
             dict(anchors_path=d / "anch_edit.jsonl", witness_path=d / "wit_tampered.jsonl"),
             dict(witness_path=d / "wit_tampered.jsonl")]
    rust_args = [dict(anchors="anch_edit.jsonl", gap=3600), dict(anchors="anch_edit.jsonl", witness="wit_tampered.jsonl"),
                 dict(witness="wit_tampered.jsonl")]
    for kw, ra in zip(cases, rust_args):
        assert py(world, **kw) == rust(world, **ra), (kw, ra)
