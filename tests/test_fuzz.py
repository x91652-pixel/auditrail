"""Property-based and mutation tests for the evidence format.

What these try to break:
  * round trip: any ledger the writer produces, with any JSON values inside, verifies
    in BOTH implementations (so canonical JSON really is reproducible across languages);
  * mutation: changing, adding or removing any field of any record, or any raw byte of
    the file, never yields an OK result with keys required unless the parsed content is
    identical to the original;
  * rehash attack: recomputing every hash after an edit is still rejected when signatures
    are required;
  * truncation: cutting records below a witnessed anchor is always reported;
  * robustness: garbage input never crashes either verifier, only gets a status;
  * differential: Python and Rust agree on the status of every input.

The Rust comparisons are skipped when the binary has not been built
(`cd verifier && cargo build --release`).
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings, strategies as st

from auditrail.anchor import FileSink, anchor_ledger
from auditrail.keys import Signer
from auditrail.ledger import GENESIS_HASH, Ledger, _canonical, record_hash
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")
needs_rust = pytest.mark.skipif(BINARY is None, reason="Rust verifier not built")

FUZZ = settings(max_examples=int(os.environ.get("AUDITRAIL_FUZZ_EXAMPLES", "60")), deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])

SIGNER = Signer.from_seed(bytes(range(7, 39)))
KEYS = {SIGNER.key_id: SIGNER.public_hex}
WORK = Path(tempfile.mkdtemp(prefix="auditrail-fuzz-"))
(WORK / "k.pub").write_text(SIGNER.public_hex, encoding="utf-8")


# ------------------------------------------------------------------ helpers

class Clock:
    def __init__(self, t=1_790_000_000):
        self.t = t

    def __call__(self):
        return self.t


def build_fixture(directory: Path):
    """A small but varied signed ledger plus a witness copy of its head."""
    directory.mkdir(parents=True, exist_ok=True)
    clock = Clock()
    led = Ledger(directory / "ledger.jsonl", signer=SIGNER, clock=clock, fsync=False)
    led.record_heartbeat(recorder_id="r", tools=["a", "b"], policy_version="p", policy_hash="e" * 64,
                         calls_attempted=0, calls_recorded=0, interval_s=60)
    for i in range(4):
        clock.t += 10
        led.record(agent_id="ag", session_id="s", policy_version="p", policy_hash="f" * 64, tool=["a", "b"][i % 2], categories=["data_access"],
                   args={"i": i}, decision="deny" if i == 2 else "allow", reason="x" if i == 2 else None, result={"i": i})
    led.record_event("a2a_send", agent_id="ag", peer="other", msg_id="m", msg_digest="0" * 64, categories=[])
    clock.t += 10
    led.record_heartbeat(recorder_id="r", tools=["a", "b"], policy_version="p", policy_hash="e" * 64,
                         calls_attempted=4, calls_recorded=4, interval_s=60)
    anchor_ledger(led, directory / "anchors.jsonl", sink=FileSink(directory / "witness.jsonl"), signer=SIGNER, clock=clock)
    return directory


FIXTURE = build_fixture(WORK / "fixture")
FIXTURE_LINES = (FIXTURE / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
FIXTURE_RECORDS = [json.loads(x) for x in FIXTURE_LINES]
WITNESS = FIXTURE / "witness.jsonl"


def write_records(path: Path, records, rehash=False):
    if rehash:
        prev = GENESIS_HASH
        for r in records:
            r["prev_hash"] = prev
            r["hash"] = record_hash(prev, r)
            prev = r["hash"]
    path.write_text("".join(_canonical(r) + "\n" for r in records), encoding="utf-8", newline="\n")


def py_verify(path, witness=None, max_gap=None, keys=KEYS):
    return verify_all(path, public_keys=keys, witness_path=witness, max_gap_s=max_gap)


def rust_verify(path, witness=None, max_gap=None, keys=True):
    cmd = [str(BINARY), str(path), "--json"]
    if keys:
        cmd += ["--pubkey", str(WORK / "k.pub")]
    if witness:
        cmd += ["--witness", str(witness)]
    if max_gap is not None:
        cmd += ["--max-gap", str(max_gap)]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert out.returncode in (0, 1), f"Rust verifier crashed (exit {out.returncode}): {out.stderr[:500]}"
    return json.loads(out.stdout)


json_scalars = st.none() | st.booleans() | st.integers(-(2 ** 53), 2 ** 53) | st.text(max_size=20)
json_values = st.recursive(
    json_scalars,
    lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=6), children, max_size=3),
    max_leaves=10,
)


# ------------------------------------------------------------------ round trip

@FUZZ
@given(payloads=st.lists(json_values, min_size=1, max_size=5), names=st.lists(st.text(max_size=12), min_size=1, max_size=5))
def test_any_ledger_the_writer_produces_verifies_in_python(payloads, names):
    path = WORK / "rt.jsonl"
    path.unlink(missing_ok=True)
    led = Ledger(path, signer=SIGNER, fsync=False)
    for i, payload in enumerate(payloads):
        led.record(agent_id=names[i % len(names)], session_id="s", policy_version="p", tool="t", categories=[names[0]],
                   args=payload, decision="allow", reason=names[-1], result=payload)
        led.record_event("a2a_send", agent_id=names[0], peer=names[-1], msg_id="m", msg_digest="0" * 64, nested=payload)
    res = py_verify(path)
    assert res["status"] == "OK", res


@needs_rust
@FUZZ
@given(payloads=st.lists(json_values, min_size=1, max_size=4), names=st.lists(st.text(max_size=12), min_size=1, max_size=4))
def test_any_ledger_the_writer_produces_verifies_in_rust_too(payloads, names):
    path = WORK / "rt2.jsonl"
    path.unlink(missing_ok=True)
    led = Ledger(path, signer=SIGNER, fsync=False)
    for i, payload in enumerate(payloads):
        led.record_event("a2a_send", agent_id=names[i % len(names)], peer=names[-1], msg_id="m", msg_digest="0" * 64,
                         nested=payload, label=names[0])
    assert py_verify(path)["status"] == "OK"
    res = rust_verify(path)
    assert res["status"] == "OK", res


# ------------------------------------------------------------------ field-level mutation

@st.composite
def field_mutations(draw):
    seq = draw(st.integers(0, len(FIXTURE_RECORDS) - 1))
    keys = sorted(FIXTURE_RECORDS[seq])
    kind = draw(st.sampled_from(["change", "delete", "add"]))
    key = draw(st.sampled_from(keys)) if kind != "add" else draw(st.text(min_size=1, max_size=8))
    value = draw(json_values)
    return seq, kind, key, value


def apply_mutation(records, seq, kind, key, value):
    rec = records[seq]
    if kind == "delete":
        rec.pop(key)
    elif kind == "change":
        assume(rec[key] != value or type(rec[key]) is not type(value))
        rec[key] = value
    else:
        assume(key not in rec)
        rec[key] = value


@FUZZ
@given(m=field_mutations())
def test_editing_any_field_of_any_record_is_never_accepted(m):
    records = json.loads(json.dumps(FIXTURE_RECORDS))
    apply_mutation(records, *m)
    path = WORK / "mut.jsonl"
    write_records(path, records)
    res = py_verify(path, witness=WITNESS, max_gap=3600)
    assert res["status"] != "OK", (m, res)


@needs_rust
@FUZZ
@given(m=field_mutations())
def test_python_and_rust_agree_on_every_field_mutation(m):
    records = json.loads(json.dumps(FIXTURE_RECORDS))
    apply_mutation(records, *m)
    path = WORK / "mut2.jsonl"
    write_records(path, records)
    p, r = py_verify(path, witness=WITNESS, max_gap=3600), rust_verify(path, witness=WITNESS, max_gap=3600)
    assert p["status"] == r["status"], (m, p, r)
    if p.get("bad_seq") is not None or r.get("bad_seq") is not None:
        assert p.get("bad_seq") == r.get("bad_seq"), (m, p, r)


@FUZZ
@given(m=field_mutations())
def test_rehashing_after_an_edit_never_gets_past_the_signatures(m):
    seq, kind, key, value = m
    assume(key not in ("hash", "prev_hash"))  # these are recomputed by the attacker, so editing them changes nothing
    records = json.loads(json.dumps(FIXTURE_RECORDS))
    apply_mutation(records, *m)
    path = WORK / "rehash.jsonl"
    write_records(path, records, rehash=True)
    assert py_verify(path)["status"] != "OK", m
    # the same edit is invisible without keys (the documented v0.1 limit), except that a broken
    # sequence number is structural and is caught either way
    if key != "seq":
        # MALFORMED_RECORD: a field the format constrains; LEGACY_FORMAT: the first record lost its `format`
        assert verify_all(path)["status"] in ("OK", "MALFORMED_RECORD", "LEGACY_FORMAT")


# ------------------------------------------------------------------ raw byte mutation

@st.composite
def byte_mutations(draw):
    data = bytearray("".join(x + "\n" for x in FIXTURE_LINES).encode("utf-8"))
    for _ in range(draw(st.integers(1, 3))):
        op = draw(st.sampled_from(["flip", "insert", "delete", "dup_line", "drop_line", "swap_lines"]))
        if op == "flip":
            data[draw(st.integers(0, len(data) - 1))] = draw(st.integers(0, 255))
        elif op == "insert":
            data[draw(st.integers(0, len(data))):0] = bytes(draw(st.lists(st.integers(0, 255), min_size=1, max_size=4)))
        elif op == "delete":
            i = draw(st.integers(0, len(data) - 1))
            del data[i:i + draw(st.integers(1, 5))]
        else:
            lines = bytes(data).split(b"\n")
            lines = [x for x in lines if x]
            if len(lines) < 2:
                continue
            i = draw(st.integers(0, len(lines) - 1))
            if op == "dup_line":
                lines.insert(i, lines[i])
            elif op == "drop_line":
                del lines[i]
            else:
                j = draw(st.integers(0, len(lines) - 1))
                lines[i], lines[j] = lines[j], lines[i]
            data = bytearray(b"\n".join(lines) + b"\n")
    return bytes(data)


def parsed_or_none(data: bytes):
    try:
        return [json.loads(x) for x in data.decode("utf-8").splitlines() if x.strip()]
    except (ValueError, UnicodeDecodeError):
        return None


@FUZZ
@given(data=byte_mutations())
def test_no_byte_level_corruption_yields_ok_unless_the_content_is_unchanged(data):
    path = WORK / "bytes.jsonl"
    path.write_bytes(data)
    res = py_verify(path, witness=WITNESS, max_gap=3600)
    assert isinstance(res, dict) and "status" in res  # never an exception
    if parsed_or_none(data) != FIXTURE_RECORDS:
        assert res["status"] != "OK", (data[:200], res)


@needs_rust
@FUZZ
@given(data=byte_mutations())
def test_python_and_rust_agree_on_every_byte_mutation(data):
    path = WORK / "bytes2.jsonl"
    path.write_bytes(data)
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        assume(False)  # the Rust CLI refuses non-UTF-8 files up front (exit 2); that is a separate, documented path
    p, r = py_verify(path, witness=WITNESS, max_gap=3600), rust_verify(path, witness=WITNESS, max_gap=3600)
    assert p["status"] == r["status"], (data[:300], p, r)


# ------------------------------------------------------------------ truncation

@FUZZ
@given(keep=st.integers(0, len(FIXTURE_LINES) - 1))
def test_cutting_records_below_a_witnessed_anchor_is_always_reported(keep):
    path = WORK / "cut.jsonl"
    path.write_text("".join(x + "\n" for x in FIXTURE_LINES[:keep]), encoding="utf-8", newline="\n")
    res = py_verify(path, witness=WITNESS)
    assert res["status"] == "TRUNCATED", res


# ------------------------------------------------------------------ robustness

@FUZZ
@given(blob=st.binary(max_size=400) | st.text(max_size=300).map(lambda s: s.encode("utf-8")))
def test_garbage_never_crashes_the_python_verifier(blob):
    path = WORK / "garbage.jsonl"
    path.write_bytes(blob)
    res = py_verify(path, witness=WITNESS, max_gap=60)
    assert isinstance(res, dict) and isinstance(res["status"], str)


@FUZZ
@given(lines=st.lists(st.dictionaries(st.sampled_from(["seq", "ts", "kind", "hash", "prev_hash", "calls_attempted",
                                                        "calls_recorded", "tools", "key_id", "sig", "format"]),
                                       json_values, max_size=8), max_size=4))
def test_structurally_wrong_records_get_a_status_not_an_exception(lines):
    path = WORK / "shape.jsonl"
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines), encoding="utf-8", newline="\n")
    res = py_verify(path, max_gap=60)
    assert isinstance(res["status"], str)
    assert res["status"] != "OK" or not lines


@needs_rust
@FUZZ
@given(lines=st.lists(st.dictionaries(st.sampled_from(["seq", "ts", "kind", "hash", "prev_hash", "calls_attempted",
                                                        "calls_recorded", "tools", "key_id", "sig", "format"]),
                                       json_values, max_size=8), max_size=4))
def test_rust_also_survives_structurally_wrong_records_and_agrees(lines):
    path = WORK / "shape2.jsonl"
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines), encoding="utf-8", newline="\n")
    assert py_verify(path, max_gap=60)["status"] == rust_verify(path, max_gap=60)["status"]
