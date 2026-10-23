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


def _many_anchors(tmp_path, n):
    """A ledger of n records and n valid unsigned v1 anchor lines (one per record), chained correctly."""
    import hashlib

    from auditrail.ledger import _canonical

    path = tmp_path / "big.jsonl"
    led = Ledger(path, fsync=False)
    for i in range(n):
        led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={"i": i},
                   decision="allow")
    records = list(led)
    prev = "0" * 64
    lines = []
    for r in records:
        body = {"anchor_version": 1, "seq": r["seq"], "head_hash": r["hash"], "prev_anchor": prev,
                "created_at": "2026-01-01T00:00:00Z"}
        h = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        lines.append(_canonical({**body, "anchor_hash": h}))
        prev = h
    (tmp_path / "anchors.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


@pytest.mark.parametrize("flag", ["--anchors", "--witness"])
def test_many_anchors_do_not_make_the_rust_verifier_quadratic(tmp_path, flag):
    """20,000 records x 20,000 anchor lines took ~50 s here when every anchor searched the ledger linearly; with an index it
    is well under a second. The limit is deliberately generous (30 s) so a slow CI machine does not make this flaky:
    it separates 'about a second' from 'minutes', not 'fast' from 'a little slower'."""
    import time

    n = 20000
    path = _many_anchors(tmp_path, n)
    start = time.monotonic()
    code, out = run(path, flag, tmp_path / "anchors.jsonl", "--json")
    elapsed = time.monotonic() - start
    assert code == 0, out
    assert out["status"] == "OK" and out["records"] == n and out["anchored_upto"] == n - 1
    assert out["unanchored_tail"] == 0
    assert elapsed < 30, f"{elapsed:.1f}s for {n} records and {n} anchors"
