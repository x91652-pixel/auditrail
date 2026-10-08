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
        led.record(agent_id="agent-1", session_id="sess-1", policy_version="vec-policy", tool="read_x" if i % 2 == 0 else "send_y",
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

    for lock in OUT.rglob("*.lock"):
        lock.unlink()
    print(f"wrote {sum(1 for p in OUT.iterdir() if p.is_dir())} cases to {OUT}")


if __name__ == "__main__":
    main()
