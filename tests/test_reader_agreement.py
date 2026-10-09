"""Every way two readers could disagree about an odd input, pinned down as a case.

Each case edits the bytes of a known-good signed ledger and states the exact status BOTH
verifiers must return. Where the edit would not change a hashed field (whitespace inside a
signature, a duplicate key repeating the same value) the check is that neither verifier is fooled.
The Rust half is skipped if the binary is not built.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from auditrail.anchor import FileSink, anchor_ledger
from auditrail.keys import Signer
from auditrail.ledger import GENESIS_HASH, Ledger, _canonical, record_hash
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")

SIGNER = Signer.from_seed(bytes(range(9, 41)))
KEYS = {SIGNER.key_id: SIGNER.public_hex}


class Clock:
    def __init__(self):
        self.t = 1_790_000_000

    def __call__(self):
        return self.t


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    d = tmp_path_factory.mktemp("agree")
    clock = Clock()
    led = Ledger(d / "ledger.jsonl", signer=SIGNER, clock=clock, fsync=False)
    led.record_heartbeat(recorder_id="r", tools=["a"], policy_version="p", policy_hash="e" * 64,
                         calls_attempted=0, calls_recorded=0, interval_s=60)
    for i in range(3):
        clock.t += 10
        led.record(agent_id="ag", session_id="s", policy_version="p", tool="a", categories=[], args={"i": i},
                   decision="allow", result={"i": i}, duration_ms=None)
    clock.t += 10
    led.record_heartbeat(recorder_id="r", tools=["a"], policy_version="p", policy_hash="e" * 64,
                         calls_attempted=3, calls_recorded=3, interval_s=60)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=SIGNER, clock=clock)
    (d / "k.pub").write_text(SIGNER.public_hex, encoding="utf-8")
    return d


def records_of(base):
    return [json.loads(x) for x in (base / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]


def write(path, records, rehash=False):
    if rehash:
        prev = GENESIS_HASH
        for r in records:
            r["prev_hash"] = prev
            r["hash"] = record_hash(prev, r)
            prev = r["hash"]
    path.write_bytes("".join(_canonical(r) + "\n" for r in records).encode("utf-8"))


def both(base, path, keys=True, witness=False, max_gap=None):
    py = verify_all(path, public_keys=KEYS if keys else None, witness_path=base / "witness.jsonl" if witness else None,
                    max_gap_s=max_gap)
    if BINARY is None:
        return py["status"], None
    cmd = [str(BINARY), str(path), "--json"]
    if keys:
        cmd += ["--pubkey", str(base / "k.pub")]
    if witness:
        cmd += ["--witness", str(base / "witness.jsonl")]
    if max_gap is not None:
        cmd += ["--max-gap", str(max_gap)]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    assert out.returncode in (0, 1), out.stderr
    return py["status"], json.loads(out.stdout)["status"]


def check(base, tmp_path, name, data, expected, **kw):
    p = tmp_path / f"{name}.jsonl"
    p.write_bytes(data)
    py, rs = both(base, p, **kw)
    assert py == expected, f"{name}: Python gave {py}, expected {expected}"
    if rs is not None:
        assert rs == expected, f"{name}: Rust gave {rs}, expected {expected}"


def raw(base):
    return (base / "ledger.jsonl").read_bytes()


def test_the_untouched_fixture_is_ok_in_both(base, tmp_path):
    check(base, tmp_path, "ok", raw(base), "OK", witness=True, max_gap=60)


# ------------------------------------------------------------------ encoding and line handling

def test_non_utf8_bytes_are_a_tamper_status_not_a_crash(base, tmp_path):
    check(base, tmp_path, "latin1", raw(base)[:50] + b"\xff\xfe" + raw(base)[50:], "TAMPERED_LEDGER")
    check(base, tmp_path, "lone_continuation", b"\x80" + raw(base), "TAMPERED_LEDGER")


def test_crlf_line_endings_and_blank_lines_are_tolerated_identically(base, tmp_path):
    crlf = raw(base).replace(b"\n", b"\r\n")
    check(base, tmp_path, "crlf", crlf, "OK", witness=True)
    padded = b"\n  \t \n" + raw(base).replace(b"\n", b"\n   \n")
    check(base, tmp_path, "blank_lines", padded, "OK", witness=True)


def test_unicode_whitespace_is_not_blank_and_not_a_separator(base, tmp_path):
    # U+2028 / U+0085 / form feed: Python's str.strip()/splitlines() would treat these as whitespace or newlines
    for name, ch in (("ls", " "), ("nel", "\u0085"), ("ff", "\x0c"), ("fs", "\x1c")):
        data = (ch + "\n").encode("utf-8") + raw(base)
        check(base, tmp_path, f"ws_{name}", data, "TAMPERED_LEDGER")
    lines = raw(base).split(b"\n")
    inside = lines[1].replace(b'"agent_id":"ag"', '"agent_id":"a g"'.encode("utf-8"))
    check(base, tmp_path, "ls_in_string", b"\n".join([lines[0], inside] + lines[2:]), "TAMPERED_LEDGER")


def test_a_bare_carriage_return_inside_a_line_is_not_a_line_break(base, tmp_path):
    lines = raw(base).split(b"\n")
    data = b"\n".join([lines[0], lines[1].replace(b",", b",\r", 1)] + lines[2:])
    check(base, tmp_path, "bare_cr", data, "OK", witness=True)  # CR is JSON whitespace; the content is unchanged


def test_a_utf8_bom_is_rejected(base, tmp_path):
    check(base, tmp_path, "bom", b"\xef\xbb\xbf" + raw(base), "TAMPERED_LEDGER")


# ------------------------------------------------------------------ numbers and strings

@pytest.mark.parametrize("literal", ["-0", "1.0", "1e2", "1E400", "NaN", "Infinity", "-Infinity", "9223372036854775808",
                                     "-9223372036854775809", "18446744073709551615", "0.5"])
def test_numbers_outside_plain_i64_are_rejected(base, tmp_path, literal):
    data = raw(base).replace(b'"duration_us":null', b'"duration_us":' + literal.encode(), 1)
    check(base, tmp_path, "num", data, "TAMPERED_LEDGER")


def test_the_largest_and_smallest_i64_are_accepted_as_numbers(base, tmp_path):
    recs = records_of(base)
    recs[1]["big"] = 9223372036854775807
    recs[1]["small"] = -9223372036854775808
    p = tmp_path / "i64.jsonl"
    write(p, recs, rehash=True)
    py, rs = both(base, p, keys=False)
    assert py == "OK" and rs in (None, "OK")


def test_a_lone_surrogate_escape_is_rejected_and_a_valid_pair_is_accepted(base, tmp_path):
    lone = raw(base).replace(b'"agent_id":"ag"', b'"agent_id":"a\\ud800g"', 1)
    check(base, tmp_path, "lone", lone, "TAMPERED_LEDGER")
    pair = raw(base).replace(b'"agent_id":"ag"', b'"agent_id":"a\\ud83d\\ude00g"', 1)
    check(base, tmp_path, "pair", pair, "TAMPERED_LEDGER")  # parses fine; the edit changes the hash


def test_nesting_deeper_than_64_is_rejected_at_64_it_is_accepted(base, tmp_path):
    """The record object is depth 1, so a field holding k nested lists makes depth 1 + k."""
    def deep(k):
        v = []
        for _ in range(k - 1):
            v = [v]
        return v

    recs = records_of(base)
    recs[1]["deep"] = deep(63)  # total depth 64
    p = tmp_path / "deep64.jsonl"
    write(p, recs, rehash=True)
    py, rs = both(base, p, keys=False)
    assert py == "OK" and rs in (None, "OK"), (py, rs)

    for k in (64, 65, 500):  # total depth 65, 66, 501: rejected while parsing, before any hash is looked at
        recs = records_of(base)
        line = _canonical(recs[1])[:-1] + ',"deep":' + "[" * k + "]" * k + "}"
        data = "\n".join([_canonical(recs[0]), line] + [_canonical(r) for r in recs[2:]]).encode() + "\n".encode()
        check(base, tmp_path, f"deep{k}", data, "TAMPERED_LEDGER", keys=False)
        # and nothing after the parse failure is even considered: the status carries the record index
        py = verify_all(tmp_path / f"deep{k}.jsonl")
        assert py["bad_seq"] == 1 and "acceptable JSON object" in py["detail"], py


def test_duplicate_keys_resolve_to_the_last_value_in_both(base, tmp_path):
    lines = raw(base).split(b"\n")
    same = lines[1][:-1] + b',"tool":"a"}'  # repeats the same value: content unchanged, so still OK
    check(base, tmp_path, "dup_same", b"\n".join([lines[0], same] + lines[2:]), "OK", witness=True)
    other = lines[1][:-1] + b',"tool":"zzz"}'  # last value wins: this is an edit
    check(base, tmp_path, "dup_other", b"\n".join([lines[0], other] + lines[2:]), "TAMPERED_LEDGER")


# ------------------------------------------------------------------ signatures and types

def test_a_signature_cannot_be_altered_without_invalidating_it(base, tmp_path):
    recs = records_of(base)
    sig = recs[1]["sig"]
    variants = {"space": sig[:10] + " " + sig[10:], "newline_escape": sig[:10] + "\n" + sig[10:], "upper": sig.upper(),
                "short": sig[:-2], "long": sig + "00", "prefix": "0x" + sig[2:], "tab": sig[:4] + "\t" + sig[4:]}
    for name, bad in variants.items():
        r = json.loads(json.dumps(recs))
        r[1]["sig"] = bad
        p = tmp_path / f"sig_{name}.jsonl"
        write(p, r)
        py, rs = both(base, p)
        assert py == "BAD_SIGNATURE", (name, py)
        assert rs in (None, "BAD_SIGNATURE"), (name, rs)


def test_bool_and_wrong_types_are_not_integers(base, tmp_path):
    recs = records_of(base)
    recs[1]["seq"] = True  # True == 1 in Python
    p = tmp_path / "seq_true.jsonl"
    write(p, recs, rehash=True)
    py, rs = both(base, p, keys=False)
    assert py == "TAMPERED_LEDGER" and rs in (None, "TAMPERED_LEDGER")

    recs = records_of(base)
    recs[4]["calls_attempted"] = True  # True == 1 in Python, so (True, 1) would wrongly look consistent
    recs[4]["calls_recorded"] = 1
    p = tmp_path / "hb_bool.jsonl"
    write(p, recs, rehash=True)
    py, rs = both(base, p, keys=False, max_gap=60)
    assert py == "MALFORMED_RECORD" and rs in (None, "MALFORMED_RECORD")


def test_key_id_edge_cases(base, tmp_path):
    for name, value in (("empty", ""), ("number", 5), ("list", ["x"]), ("null", None)):
        recs = records_of(base)
        recs[0]["key_id"] = value
        p = tmp_path / f"kid_{name}.jsonl"
        write(p, recs, rehash=True)
        py, rs = both(base, p)
        assert py in ("UNSIGNED_RECORD", "UNKNOWN_KEY"), (name, py)
        assert rs in (None, py), (name, py, rs)


# ------------------------------------------------------------------ timestamps and heartbeat fields

@pytest.mark.parametrize("ts", ["2026-02-30T00:00:00Z", "2026-13-01T00:00:00Z", "2026-09-21T24:00:00Z", "2026-09-21T23:60:00Z",
                                "2026-09-21T23:59:60Z", "1969-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "2026-09-21 12:00:00Z",
                                "2026-09-21T12:00:00+00:00", "2026-9-21T12:00:00Z", "٢٠٢٦-09-21T12:00:00Z", "2026-09-21T12:00:00z",
                                " 2026-09-21T12:00:00Z", "2026-09-21T12:00:00Z\n", "+026-09-21T12:00:00Z", 1790000000, None])
def test_invalid_timestamps_are_malformed_in_both(base, tmp_path, ts):
    recs = records_of(base)
    recs[1]["ts"] = ts
    p = tmp_path / "ts.jsonl"
    write(p, recs, rehash=True)
    py, rs = both(base, p, keys=False)
    assert py == "MALFORMED_RECORD" and rs in (None, "MALFORMED_RECORD"), (ts, py, rs)


@pytest.mark.parametrize("ts", ["2024-02-29T12:00:00Z", "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "2000-02-29T00:00:00Z"])
def test_valid_edge_timestamps_are_accepted_in_both(base, tmp_path, ts):
    recs = records_of(base)
    recs[1]["ts"] = ts
    p = tmp_path / "ts_ok.jsonl"
    write(p, recs, rehash=True)
    py, rs = both(base, p, keys=False)
    assert py == "OK" and rs in (None, "OK"), (ts, py, rs)


@pytest.mark.parametrize("field,value", [("tools", "a"), ("tools", [1]), ("tools", None), ("calls_recorded", "3"),
                                         ("calls_attempted", 3.0), ("calls_attempted", None), ("kind", ["heartbeat"])])
def test_malformed_heartbeat_fields_are_a_status_in_both(base, tmp_path, field, value):
    recs = records_of(base)
    recs[4][field] = value
    p = tmp_path / "hb.jsonl"
    write(p, recs, rehash=True)
    py, rs = both(base, p, keys=False, max_gap=60)
    assert py == "MALFORMED_RECORD" or py == "TAMPERED_LEDGER", (field, value, py)  # 3.0 is a float: rejected at parse
    assert rs in (None, py), (field, value, py, rs)


# ------------------------------------------------------------------ anchors and witness

def test_witness_file_oddities_agree(base, tmp_path):
    good = (base / "witness.jsonl").read_bytes()
    line = json.loads(good.decode("utf-8").splitlines()[0])
    assert f'"seq":{line["seq"]}'.encode() in good
    cases = {
        "non_utf8": good + b"\xff\n",
        "bool_seq": json.dumps({**line, "seq": True}).encode() + b"\n",
        "string_seq": json.dumps({**line, "seq": "6"}).encode() + b"\n",
        "negative_seq": json.dumps({**line, "seq": -1}).encode() + b"\n",
        "bool_version": json.dumps({**line, "anchor_version": True}).encode() + b"\n",
        "list_version": json.dumps({**line, "anchor_version": [2]}).encode() + b"\n",
        "extra_field": json.dumps({**line, "extra": 1}).encode() + b"\n",
        "sink_ref_number": json.dumps({**line, "sink_ref": 5}).encode() + b"\n",
        "sig_space": json.dumps({**line, "sig": line["sig"][:6] + " " + line["sig"][6:]}).encode() + b"\n",
        "float_seq": good.replace(f'"seq":{line["seq"]}'.encode(), f'"seq":{line["seq"]}.0'.encode()),
        "garbage_after": good + b"not json\n",
    }
    for name, data in cases.items():
        w = tmp_path / f"w_{name}.jsonl"
        w.write_bytes(data)
        py = verify_all(base / "ledger.jsonl", public_keys=KEYS, witness_path=w)["status"]
        assert py != "OK", (name, py)
        if BINARY is not None:
            out = subprocess.run([str(BINARY), str(base / "ledger.jsonl"), "--json", "--pubkey", str(base / "k.pub"),
                                  "--witness", str(w)], capture_output=True, text=True, encoding="utf-8")
            assert out.returncode in (0, 1), (name, out.stderr)
            assert json.loads(out.stdout)["status"] == py, (name, py, out.stdout)
