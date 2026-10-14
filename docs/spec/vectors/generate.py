"""Generate the conformance test vectors for docs/spec/evidence-format-v2.md.

Everything is deterministic (fixed Ed25519 seeds, fixed clock), so running this
twice produces byte-identical files; tests/test_vectors.py checks that. Any
verifier, in any language, must report `expected.json`'s status for each case.

    python docs/spec/vectors/generate.py
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from auditrail.anchor import FileSink, anchor_ledger  # noqa: E402
from auditrail.keys import Signer  # noqa: E402
from auditrail.ledger import GENESIS_HASH, Ledger, _canonical, record_hash  # noqa: E402

OUT = Path(__file__).resolve().parent
T0 = 1_790_000_000  # 2026-09-21T13:33:20Z
RECORDER_SEED = bytes(range(32))
OTHER_SEED = bytes(range(32, 64))


class Clock:
    def __init__(self, t: int = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def put(path: Path, text: str) -> None:
    """Write text with LF endings on every OS, so the vectors are byte-identical everywhere."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def build(case_dir: Path, signer: Signer, clock: Clock, n_calls: int = 5):
    case_dir.mkdir(parents=True, exist_ok=True)
    led = Ledger(case_dir / "ledger.jsonl", signer=signer, clock=clock, fsync=False)
    led.record_heartbeat(recorder_id="vec", tools=["read_x", "send_y"], policy_version="vec-policy",
                         policy_hash="ab" * 32, calls_attempted=0, calls_recorded=0, interval_s=60)
    for i in range(n_calls):
        clock.t += 10
        led.record(agent_id="agent-1", session_id="sess-1", policy_version="vec-policy", policy_hash="ab" * 32,
                   tool="read_x" if i % 2 == 0 else "send_y",
                   categories=["data_access"] if i % 2 == 0 else ["external_comm"], args={"i": i, "名稱": "測試"},
                   decision="deny" if i == 3 else "allow", reason="lethal_trifecta" if i == 3 else None,
                   result={"ok": i} if i != 3 else None, duration_ms=1.5)
    clock.t += 10
    led.record_heartbeat(recorder_id="vec", tools=["read_x", "send_y"], policy_version="vec-policy",
                         policy_hash="ab" * 32, calls_attempted=n_calls, calls_recorded=n_calls, interval_s=60)
    put(case_dir / "recorder.pub", signer.public_hex + "\n")
    return led


def rewrite(path: Path, fn, rehash: bool):
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    fn(recs)
    if rehash:
        prev = GENESIS_HASH
        for r in recs:
            r["prev_hash"] = prev
            r["hash"] = record_hash(prev, r)
            prev = r["hash"]
    put(path, "".join(_canonical(r) + "\n" for r in recs))


def write_expected(case_dir: Path, expected: dict, args: dict | None = None):
    put(case_dir / "expected.json", json.dumps({"args": args or {}, **expected}, indent=2, sort_keys=True) + "\n")


def main() -> None:
    for child in OUT.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
    signer = Signer.from_seed(RECORDER_SEED)

    # 1. valid, signed, witnessed
    d = OUT / "01-valid-signed-witnessed"
    clock = Clock()
    led = build(d, signer, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=signer, clock=clock)
    write_expected(d, {"status": "OK", "anchored_upto": 6, "unanchored_tail": 0},
                   {"require_signatures": True, "witness": "witness.jsonl", "max_gap_s": 60})

    # 2. valid chain, no keys given: OK, and the verifier must say what it did not check
    d = OUT / "02-valid-unsigned-check"
    build(d, signer, Clock())
    write_expected(d, {"status": "OK", "anchored_upto": None, "unanchored_tail": 7}, {})

    # 3. one field edited, hashes NOT recomputed
    d = OUT / "03-edited-record"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[4].update(decision="allow"), rehash=False)
    write_expected(d, {"status": "TAMPERED_LEDGER", "bad_seq": 4}, {})

    # 4. edited AND every hash recomputed: passes without keys, fails with signatures
    d = OUT / "04-rewritten-and-rehashed"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[4].update(decision="allow", reason=None), rehash=True)
    write_expected(d, {"status": "BAD_SIGNATURE", "bad_seq": 4}, {"require_signatures": True})

    # 5. same attack, but a verifier given no keys cannot see it (the documented limit)
    d = OUT / "05-rewritten-rehashed-no-keys"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[4].update(decision="allow", reason=None), rehash=True)
    write_expected(d, {"status": "OK", "anchored_upto": None, "unanchored_tail": 7}, {})

    # 6. tail cut off after a witnessed anchor
    d = OUT / "06-truncated-after-witnessed-anchor"
    clock = Clock()
    led = build(d, signer, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=signer, clock=clock)
    lines = (d / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    put(d / "ledger.jsonl", "\n".join(lines[:4]) + "\n")
    write_expected(d, {"status": "TRUNCATED"}, {"require_signatures": True, "witness": "witness.jsonl"})

    # 7. whole ledger rebuilt by someone holding a different key; owner's anchors file deleted
    d = OUT / "07-rebuilt-with-other-key"
    clock = Clock()
    led = build(d, signer, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=signer, clock=clock)
    (d / "anchors.jsonl").unlink()
    (d / "ledger.jsonl").unlink()
    other = Signer.from_seed(OTHER_SEED)
    build(d, other, Clock())
    put(d / "recorder.pub", signer.public_hex + "\n")  # verifier trusts the REAL key
    write_expected(d, {"status": "UNKNOWN_KEY", "bad_seq": 0}, {"require_signatures": True, "witness": "witness.jsonl"})

    # 8. recorder silent for an hour
    d = OUT / "08-heartbeat-gap"
    clock = Clock()
    led = Ledger(d / "ledger.jsonl", signer=signer, clock=clock, fsync=False) if (d.mkdir(parents=True) or True) else None
    for gap in (0, 60, 3600):
        clock.t += gap
        led.record_heartbeat(recorder_id="vec", tools=["read_x"], policy_version="p", policy_hash="cd" * 32,
                             calls_attempted=0, calls_recorded=0, interval_s=60)
    put(d / "recorder.pub", signer.public_hex + "\n")
    write_expected(d, {"status": "HEARTBEAT_GAP"}, {"require_signatures": True, "max_gap_s": 120})

    # 9. a heartbeat admits calls ran without being recorded
    d = OUT / "09-unrecorded-calls"
    d.mkdir(parents=True)
    led = Ledger(d / "ledger.jsonl", signer=signer, clock=Clock(), fsync=False)
    led.record_heartbeat(recorder_id="vec", tools=["read_x"], policy_version="p", policy_hash="cd" * 32,
                         calls_attempted=3, calls_recorded=2, interval_s=60)
    put(d / "recorder.pub", signer.public_hex + "\n")
    write_expected(d, {"status": "UNRECORDED_CALLS", "bad_seq": 0}, {"require_signatures": True, "max_gap_s": 3600})

    # 10. records reordered
    d = OUT / "10-reordered"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r.__setitem__(slice(2, 4), [r[3], r[2]]), rehash=False)
    write_expected(d, {"status": "TAMPERED_LEDGER", "bad_seq": 2}, {})

    # 11. hashed and signed correctly, but a field the format constrains is nonsense (Feb 30)
    d = OUT / "11-malformed-timestamp"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[2].update(ts="2026-02-30T00:00:00Z"), rehash=True)
    write_expected(d, {"status": "MALFORMED_RECORD", "bad_seq": 2}, {})

    # 14. hashed and signed correctly, but policy_hash is not a hash
    d = OUT / "14-malformed-policy-hash"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[2].update(policy_hash="policy-v1"), rehash=True)
    write_expected(d, {"status": "MALFORMED_RECORD", "bad_seq": 2}, {})

    # 15. a genuine v0.1 ledger (written by the real v0.1 code; holds floats, has no `format`): not judged, not an alarm
    d = OUT / "15-legacy-v01"
    d.mkdir(parents=True)
    legacy = (ROOT / "tests" / "fixtures" / "legacy_v01_ledger.jsonl").read_bytes()
    (d / "ledger.jsonl").write_bytes(legacy)
    write_expected(d, {"status": "LEGACY_FORMAT"}, {})

    # 12. a float where only integers are allowed: rejected while parsing, before any hash is looked at
    d = OUT / "12-float-in-record"
    build(d, signer, Clock())
    text = (d / "ledger.jsonl").read_text(encoding="utf-8")
    assert '"duration_us":1500' in text
    put(d / "ledger.jsonl", text.replace('"duration_us":1500', '"duration_us":1500.0', 1))
    write_expected(d, {"status": "TAMPERED_LEDGER", "bad_seq": 1}, {})

    # 13. not UTF-8
    d = OUT / "13-not-utf8"
    build(d, signer, Clock())
    data = (d / "ledger.jsonl").read_bytes()
    (d / "ledger.jsonl").write_bytes(data[:100] + b"\xff\xfe" + data[100:])
    write_expected(d, {"status": "TAMPERED_LEDGER"}, {})

    # ---- 16-24: optional signature-algorithm and format identifiers (D-11). Added after the original 15,
    # which are untouched: a record without `sig_alg` means ed25519 and is byte-identical to before.
    class FutureSigner(Signer):
        """Signs with the same Ed25519 key but declares an algorithm token this verifier set does not implement."""

        alg = "x-future-alg"

    future = FutureSigner.from_seed(RECORDER_SEED)

    # 16. written by a writer using an algorithm no verifier here implements; keys are given
    d = OUT / "16-unsupported-algorithm"
    build(d, future, Clock())
    assert b'"sig_alg":"x-future-alg"' in (d / "ledger.jsonl").read_bytes()
    write_expected(d, {"status": "UNSUPPORTED_ALGORITHM", "bad_seq": 0}, {"require_signatures": True})

    # 17. the same bytes, no keys given: signatures are not checked anyway, so this is OK (and says what it skipped)
    d = OUT / "17-unsupported-algorithm-no-keys"
    build(d, future, Clock())
    write_expected(d, {"status": "OK", "anchored_upto": None, "unanchored_tail": 7}, {})

    # 18. sig_alg is not a token of the grammar (upper case)
    d = OUT / "18-sig-alg-upper-case"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[2].update(sig_alg="ES256"), rehash=True)
    write_expected(d, {"status": "MALFORMED_RECORD", "bad_seq": 2}, {"require_signatures": True})

    # 19. a token followed by a newline is not a token
    d = OUT / "19-sig-alg-trailing-newline"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[2].update(sig_alg="x-future-alg\n"), rehash=True)
    write_expected(d, {"status": "MALFORMED_RECORD", "bad_seq": 2}, {"require_signatures": True})

    # 20. the default written out: one meaning, one encoding
    d = OUT / "20-sig-alg-explicit-ed25519"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[2].update(sig_alg="ed25519"), rehash=True)
    write_expected(d, {"status": "MALFORMED_RECORD", "bad_seq": 2}, {"require_signatures": True})

    # 21. a record of another format that still chains is declined, not misread
    d = OUT / "21-format-3"
    build(d, signer, Clock())
    rewrite(d / "ledger.jsonl", lambda r: r[2].update(format=3), rehash=True)
    write_expected(d, {"status": "UNSUPPORTED_FORMAT", "bad_seq": 2}, {})

    # 22. a signed anchor of anchor_version 3 naming an algorithm nobody here implements
    d = OUT / "22-anchor-v3-unsupported-algorithm"
    clock = Clock()
    led = build(d, signer, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=future, clock=clock)
    assert json.loads((d / "witness.jsonl").read_text(encoding="utf-8").splitlines()[0])["anchor_version"] == 3
    write_expected(d, {"status": "UNSUPPORTED_ALGORITHM"}, {"require_signatures": True, "witness": "witness.jsonl"})

    # 23. an anchor_version 2 line that carries sig_alg: not allowed there
    d = OUT / "23-anchor-v2-with-sig-alg"
    clock = Clock()
    led = build(d, signer, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=signer, clock=clock)
    line = json.loads((d / "witness.jsonl").read_text(encoding="utf-8").splitlines()[0])
    line["sig_alg"] = "x-future-alg"
    put(d / "witness.jsonl", _canonical(line) + "\n")
    write_expected(d, {"status": "TAMPERED_ANCHOR"}, {"require_signatures": True, "witness": "witness.jsonl"})

    # 24. anchor_version 3 with the default spelled out
    d = OUT / "24-anchor-v3-explicit-ed25519"
    clock = Clock()
    led = build(d, signer, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=future, clock=clock)
    line = json.loads((d / "witness.jsonl").read_text(encoding="utf-8").splitlines()[0])
    line["sig_alg"] = "ed25519"
    body = {k: line[k] for k in ("anchor_version", "seq", "head_hash", "prev_anchor", "created_at", "key_id", "sig_alg")}
    import hashlib

    line["anchor_hash"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    put(d / "witness.jsonl", _canonical(line) + "\n")
    write_expected(d, {"status": "TAMPERED_ANCHOR"}, {"require_signatures": True, "witness": "witness.jsonl"})

    # ---- 25-32: an inconclusive status (UNSUPPORTED_*) must never hide definite evidence. An attacker without
    # the key can add a sig_alg or set format to 3 at will, so whenever a witness or a signature can still show
    # tampering, that is what is reported.
    def witnessed(name, mutate, keep_len=None):
        d = OUT / name
        clock = Clock()
        led = build(d, signer, clock)
        anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=signer, clock=clock)
        (d / "anchors.jsonl").unlink()  # the owner's file is gone; only the witness copy and the key remain
        if keep_len is not None:
            lines = (d / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
            put(d / "ledger.jsonl", "\n".join(lines[:keep_len]) + "\n")
        rewrite(d / "ledger.jsonl", mutate, rehash=True)
        return d

    # 25. a middle record edited, chain re-hashed, a sig_alg added to it; keys + witness: the next record's old
    # signature no longer matches its new hash
    d = witnessed("25-rehash-add-sig-alg-keys-and-witness",
                  lambda r: r[2].update(decision="allow", reason=None, sig_alg="x-future-alg"))
    write_expected(d, {"status": "BAD_SIGNATURE", "bad_seq": 3}, {"require_signatures": True, "witness": "witness.jsonl"})

    # 26. the LAST record edited and given a sig_alg (nothing after it to expose the stale signature): the
    # witness still holds the real head, so the rewrite is found
    d = witnessed("26-rewrite-last-record-sig-alg-keys-and-witness",
                  lambda r: r[-1].update(calls_attempted=99, sig_alg="x-future-alg"))
    write_expected(d, {"status": "REWRITTEN", "bad_seq": 6}, {"require_signatures": True, "witness": "witness.jsonl"})

    # 27. the same but format set to 3: the record is still signed as ed25519, and its signature does not verify
    d = witnessed("27-rewrite-last-record-format-3-keys-and-witness",
                  lambda r: r[-1].update(calls_attempted=99, format=3))
    write_expected(d, {"status": "BAD_SIGNATURE", "bad_seq": 6}, {"require_signatures": True, "witness": "witness.jsonl"})

    # 28. no keys at all, only the witness copy: format 3 does not hide the rewrite
    d = witnessed("28-rewrite-format-3-witness-only",
                  lambda r: r[2].update(decision="allow", reason=None, format=3))
    write_expected(d, {"status": "REWRITTEN", "bad_seq": 6}, {"witness": "witness.jsonl"})

    # 29. witness only, sig_alg added
    d = witnessed("29-rewrite-sig-alg-witness-only",
                  lambda r: r[2].update(decision="allow", reason=None, sig_alg="x-future-alg"))
    write_expected(d, {"status": "REWRITTEN", "bad_seq": 6}, {"witness": "witness.jsonl"})

    # 30. tail cut off and the last remaining record given format 3: still TRUNCATED
    d = witnessed("30-truncated-format-3-witness-only", lambda r: r[-1].update(format=3), keep_len=4)
    write_expected(d, {"status": "TRUNCATED"}, {"witness": "witness.jsonl"})

    # 31. a genuine ledger and anchors from a writer using an algorithm nobody here implements: inconclusive,
    # with the coverage still reported
    d = OUT / "31-future-writer-keys-and-witness"
    clock = Clock()
    led = build(d, future, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=future, clock=clock)
    write_expected(d, {"status": "UNSUPPORTED_ALGORITHM", "bad_seq": 0, "anchored_upto": 6, "unanchored_tail": 0},
                   {"require_signatures": True, "witness": "witness.jsonl"})

    # 32. the same bytes and no keys: nothing was asked to be checked, so OK, and the anchors still match
    d = OUT / "32-future-writer-witness-only"
    clock = Clock()
    led = build(d, future, clock)
    anchor_ledger(led, d / "anchors.jsonl", sink=FileSink(d / "witness.jsonl"), signer=future, clock=clock)
    write_expected(d, {"status": "OK", "anchored_upto": 6, "unanchored_tail": 0}, {"witness": "witness.jsonl"})

    for lock in OUT.rglob("*.lock"):
        lock.unlink()
    print(f"wrote {sum(1 for p in OUT.iterdir() if p.is_dir())} cases to {OUT}")


if __name__ == "__main__":
    main()
