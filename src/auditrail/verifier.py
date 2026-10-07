"""Full, offline verification of an evidence ledger (spec section 7).

Order of checks, stopping at the first failure:
  1. chain        every record's seq, prev_hash and hash recompute correctly
  2. signatures   with public keys given, every record is signed by a known key
  3. anchors      the local anchors file, if given (anchor.verify_anchors)
  4. witness      a copy of what was published to a witness, if given: each
                  published anchor is genuine and still matches the ledger
  5. heartbeats   with max_gap_s given: no silent period longer than that,
                  and no writer reports calls it intercepted but did not record
Then, on success, the report lists what changed over time (tool set, policy
hash) and what is NOT covered (records after the last anchor).

verifier/ (Rust) implements the same checks independently; the test vectors in
docs/spec/vectors/ must give the same status in both.
"""
from __future__ import annotations

import calendar
import json
import time
from pathlib import Path
from typing import Any, Optional

from .keys import TAG_RECORD, verify_sig
from .ledger import GENESIS_HASH, record_hash


def _fail(status: str, detail: str, **extra: Any) -> dict:
    return {"status": status, "detail": detail, **extra}


def _read_records(path: Path) -> tuple[list[dict], Optional[dict]]:
    records: list[dict] = []
    if not path.exists():
        return records, None
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("record is not a JSON object")
            except ValueError:
                return records, _fail("TAMPERED_LEDGER", f"record #{len(records)} is not valid JSON", bad_seq=len(records))
            records.append(rec)
    return records, None


def check_chain(path, public_keys: Optional[dict[str, str]] = None, records: Optional[list[dict]] = None) -> Optional[dict]:
    """Checks 1 and 2. Returns None when the chain (and signatures, if keys given) hold.

    When public_keys is given, EVERY record must be signed by one of them. An
    unsigned record is a failure, not a pass: otherwise an attacker could rewrite
    the chain and simply leave the signatures off.
    """
    if records is None:
        records, problem = _read_records(Path(path))
        if problem is not None:
            return problem
    prev = GENESIS_HASH
    for expected, rec in enumerate(records):
        if rec.get("seq") != expected:
            return _fail("TAMPERED_LEDGER", f"expected seq={expected}, found seq={rec.get('seq')!r}", bad_seq=expected)
        if rec.get("prev_hash") != prev:
            return _fail("TAMPERED_LEDGER", f"seq={expected}: prev_hash does not link to the previous record", bad_seq=expected)
        stored = rec.get("hash")
        if not isinstance(stored, str) or record_hash(prev, rec) != stored:
            return _fail("TAMPERED_LEDGER", f"seq={expected}: hash does not match the record's contents", bad_seq=expected)
        if public_keys is not None:
            key_id, sig = rec.get("key_id"), rec.get("sig")
            if not key_id or not sig:
                return _fail("UNSIGNED_RECORD", f"seq={expected} carries no signature, but signatures are required", bad_seq=expected)
            pub = public_keys.get(key_id)
            if pub is None:
                return _fail("UNKNOWN_KEY", f"seq={expected} is signed by key_id={key_id}, which is not in the trusted keys", bad_seq=expected)
            if not verify_sig(pub, TAG_RECORD, stored.encode("ascii"), sig):
                return _fail("BAD_SIGNATURE", f"seq={expected}: signature does not verify", bad_seq=expected)
        prev = stored
    return None


def _epoch(ts: str) -> int:
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))


def check_heartbeats(records: list[dict], max_gap_s: int) -> tuple[Optional[dict], list[dict]]:
    """Check 5. Returns (problem, changes)."""
    beats = [r for r in records if r.get("kind") == "heartbeat"]
    changes: list[dict] = []
    if not beats:
        if records:
            return _fail("NO_HEARTBEAT", "a maximum gap was given but the ledger has no heartbeat records"), changes

    # gaps: start -> first beat, beat -> beat, last beat -> last record
    points = [_epoch(records[0]["ts"])] if records else []
    points += [_epoch(b["ts"]) for b in beats]
    if records:
        points.append(_epoch(records[-1]["ts"]))
    gaps = []
    for a, b in zip(points, points[1:]):
        if b - a > max_gap_s:
            gaps.append({"from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a)),
                         "to": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(b)), "seconds": b - a})

    # every writer reports how many calls it intercepted vs. managed to record
    for b in beats:
        if b.get("calls_attempted") != b.get("calls_recorded"):
            return _fail("UNRECORDED_CALLS",
                         f"heartbeat seq={b['seq']} from {b.get('recorder_id')!r}: {b.get('calls_attempted')} call(s) "
                         f"intercepted but only {b.get('calls_recorded')} recorded", bad_seq=b["seq"]), changes

    prev = None
    for b in beats:
        if prev is not None:
            added = sorted(set(b.get("tools", [])) - set(prev.get("tools", [])))
            removed = sorted(set(prev.get("tools", [])) - set(b.get("tools", [])))
            policy_changed = b.get("policy_hash") != prev.get("policy_hash")
            if added or removed or policy_changed:
                changes.append({"seq": b["seq"], "ts": b["ts"], "tools_added": added, "tools_removed": removed,
                                "policy_changed": policy_changed, "policy_version": b.get("policy_version")})
        prev = b

    if gaps:
        return _fail("HEARTBEAT_GAP", f"{len(gaps)} period(s) longer than {max_gap_s}s with no heartbeat", gaps=gaps), changes
    return None, changes


def verify_all(
    ledger_path,
    *,
    public_keys: Optional[dict[str, str]] = None,
    anchors_path=None,
    sinks: Optional[dict] = None,
    witness_path=None,
    max_gap_s: Optional[int] = None,
) -> dict:
    """Run every check that the given inputs allow. Returns a report dict with a `status`."""
    from .anchor import verify_anchors, verify_witness_file

    ledger_path = Path(ledger_path)
    records, problem = _read_records(ledger_path)
    if problem is None:
        problem = check_chain(ledger_path, public_keys=public_keys, records=records)
    if problem is not None:
        return problem

    kinds: dict[str, int] = {}
    for r in records:
        k = r.get("kind", "call")
        kinds[k] = kinds.get(k, 0) + 1
    base = {"records": len(records), "kinds": kinds, "signatures_checked": public_keys is not None}

    anchored_upto = None
    if anchors_path is not None:
        res = verify_anchors(ledger_path, anchors_path, sinks=sinks, public_keys=public_keys)
        if res["status"] != "OK":
            return {**res, **base}
        anchored_upto = res["anchored_upto"]
    if witness_path is not None:
        res = verify_witness_file(records, witness_path, public_keys=public_keys)
        if res["status"] != "OK":
            return {**res, **base}
        if res["anchored_upto"] is not None:
            anchored_upto = max(anchored_upto if anchored_upto is not None else -1, res["anchored_upto"])

    changes: list[dict] = []
    if max_gap_s is not None:
        problem, changes = check_heartbeats(records, max_gap_s)
        if problem is not None:
            return {**problem, **base}

    tail = len(records) - (anchored_upto + 1) if anchored_upto is not None else len(records)
    notes = []
    if public_keys is None:
        notes.append("signatures NOT checked (no public key given): anyone with write access could have rewritten the chain")
    if anchors_path is None and witness_path is None:
        notes.append("no anchors or witness given: truncation and whole-chain rewrites are not detectable")
    elif tail:
        notes.append(f"{tail} record(s) after the last anchor are not covered by any anchor")
    if max_gap_s is None:
        notes.append("heartbeats NOT checked (no max gap given): silent periods are not detectable")
    detail = f"{len(records)} record(s), chain intact" + (", all signatures valid" if public_keys is not None else "")
    return {"status": "OK", "detail": detail, **base, "anchored_upto": anchored_upto,
            "unanchored_tail": tail, "changes": changes, "notes": notes}
