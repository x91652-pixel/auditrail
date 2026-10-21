"""Differential test: a ledger written by the Python implementation, with awkward strings,
must verify in the independent Rust verifier. Skipped when the binary has not been built
(`cd verifier && cargo build --release`)."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from auditrail import Guard, Ledger, PolicyEngine, Signer
from auditrail.anchor import FileSink, anchor_ledger

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / name for name in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")
pytestmark = pytest.mark.skipif(BINARY is None, reason="Rust verifier not built")

AWKWARD = [
    'quote " and backslash ' + chr(92) + ' and double ' + chr(92) * 2 + ' and slash /',
    "control \x01\x1f and tab\tnewline\n and DEL \x7f",
    "emoji 😀 and CJK 測試 and combining é",
    "line sep \u2028 and para sep \u2029",
    "\ud7ff\ue000\uffff boundaries",
    "",
]


def run(*args):
    out = subprocess.run([str(BINARY), *map(str, args)], capture_output=True, text=True, encoding="utf-8")
    return out.returncode, json.loads(out.stdout) if "--json" in args else out.stdout


def test_awkward_strings_hash_identically_in_both_languages(tmp_path):
    signer = Signer.generate()
    path, witness = tmp_path / "l.jsonl", tmp_path / "w.jsonl"
    led = Ledger(path, signer=signer, fsync=False)
    for i, text in enumerate(AWKWARD):
        led.record(agent_id=text or "empty", session_id="s", policy_version="v", tool=f"t{i}", categories=[text],
                   args={text: text}, decision="deny", reason=text)
    led.record_event("a2a_send", agent_id="a", peer=AWKWARD[2], msg_digest="00" * 32, nested={"z": [AWKWARD[1], {"a": 1}], "b": None, "c": True})
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(witness), signer=signer)
    (tmp_path / "k.pub").write_text(signer.public_hex, encoding="utf-8")
    code, out = run(path, "--pubkey", tmp_path / "k.pub", "--witness", witness, "--json")
    assert code == 0, out
    assert out["status"] == "OK" and out["records"] == len(AWKWARD) + 1 and out["unanchored_tail"] == 0


def test_guard_pipeline_output_verifies_in_rust_and_a_rewrite_does_not(tmp_path):
    signer = Signer.generate()
    cfg = {"version": "v", "agents": {"a": {"allowed_tools": ["t"], "tool_categories": {"t": []}}}}
    guard = Guard(PolicyEngine(cfg), Ledger(tmp_path / "l.jsonl", signer=signer, fsync=False))
    t = guard.guarded_tool("t")(lambda x: {"x": x})
    for i in range(4):
        t(guard.session("a"), i)
    guard.heartbeat()
    (tmp_path / "k.pub").write_text(signer.public_hex, encoding="utf-8")
    code, out = run(tmp_path / "l.jsonl", "--pubkey", tmp_path / "k.pub", "--max-gap", 60, "--json")
    assert code == 0 and out["status"] == "OK"

    recs = [json.loads(x) for x in (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    recs[1]["tool"] = "something_else"
    (tmp_path / "bad.jsonl").write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in recs), encoding="utf-8")
    code, out = run(tmp_path / "bad.jsonl", "--pubkey", tmp_path / "k.pub", "--json")
    assert code == 1 and out["status"] == "TAMPERED_LEDGER" and out["bad_seq"] == 1


def test_an_empty_witness_gets_the_same_tail_note_in_both_verifiers(tmp_path):
    """Anchors were given but none exists: every record is outside any anchor, and both say so in the same words."""
    path = tmp_path / "l.jsonl"
    led = Ledger(path, signer=Signer.generate(), fsync=False)
    for i in range(3):
        led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={"i": i},
                   decision="allow")
    (tmp_path / "empty-witness.jsonl").write_text("", encoding="utf-8")
    code, rust_text = run(path, "--witness", tmp_path / "empty-witness.jsonl")
    assert code == 0
    py = subprocess.run([sys.executable, "-m", "auditrail.cli", "verify", str(path), "--witness-file",
                         str(tmp_path / "empty-witness.jsonl")], capture_output=True, text=True, encoding="utf-8",
                        cwd=ROOT)
    assert py.returncode == 0
    note = "3 record(s) after the last anchor are not covered by any anchor"
    assert note in py.stdout, py.stdout
    assert note in rust_text, rust_text
    # the JSON structure is unchanged
    code, js = run(path, "--witness", tmp_path / "empty-witness.jsonl", "--json")
    assert js["anchored_upto"] is None and js["unanchored_tail"] == 3


def test_the_spec_statements_about_anchor_floats_and_unreadable_witnesses_hold(tmp_path):
    """Pins docs/spec 'What could not be read covers': a float in an anchor line is TAMPERED_ANCHOR in both programs;
    an unreadable witness is SINK_UNREACHABLE (exit 1) in Python and an [ERROR] (exit 2) in Rust."""
    signer = Signer.generate()
    path = tmp_path / "l.jsonl"
    led = Ledger(path, signer=signer, fsync=False)
    led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={}, decision="allow")
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(tmp_path / "w.jsonl"), signer=signer)
    (tmp_path / "k.pub").write_text(signer.public_hex, encoding="utf-8")
    line = json.loads((tmp_path / "w.jsonl").read_text(encoding="utf-8").splitlines()[0])
    line["seq"] = 0.0
    (tmp_path / "wf.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")

    def py(*args):
        r = subprocess.run([sys.executable, "-m", "auditrail.cli", "verify", str(path), *map(str, args)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=ROOT)
        return r.returncode, r.stdout

    code, out = py("--witness-file", tmp_path / "wf.jsonl", "--pubkey", tmp_path / "k.pub")
    assert code == 1 and "TAMPERED_ANCHOR" in out and "malformed anchor line" in out
    code, out = run(path, "--witness", tmp_path / "wf.jsonl", "--pubkey", tmp_path / "k.pub")
    assert code == 1 and "TAMPERED_ANCHOR" in out

    code, out = py("--witness-file", tmp_path / "missing.jsonl")
    assert code == 1 and "SINK_UNREACHABLE" in out
    r = subprocess.run([str(BINARY), str(path), "--witness", str(tmp_path / "missing.jsonl")], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 2 and "[ERROR]" in r.stderr and "SINK_UNREACHABLE" not in r.stdout + r.stderr
