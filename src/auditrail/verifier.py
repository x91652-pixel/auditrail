"""Full, offline verification of an evidence ledger (spec section 6).

Order of checks, stopping at the first failure:
  1. chain        every record's seq, prev_hash and hash recompute correctly
  2. signatures   with public keys given, every record is signed by a known key
     (1 and 2 run per record, so a record is judged before the next one is looked at;
      each record must then pass the field checks of spec section 3)
  3. anchors      the local anchors file, if given (anchor.verify_anchors)
  4. witness      a copy of what was published to a witness, if given: each
                  published anchor is genuine and still matches the ledger
  5. heartbeats   with max_gap_s given: no silent period longer than that,
                  and no writer reports calls it intercepted but did not record
Then, on success, the report lists what changed over time (tool set, policy
hash) and what is NOT covered (records after the last anchor).

How files are read is fixed by _strict.py, so that this and the Rust verifier
(verifier/) cannot disagree about an odd input. The test vectors in
docs/spec/vectors/ and tests/test_fuzz.py hold them to the same answers.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

from . import _strict
from .keys import TAG_RECORD, verify_sig
from .ledger import GENESIS_HASH, record_hash


def _fail(status: str, detail: str, **extra: Any) -> dict:
    return {"status": status, "detail": detail, **extra}


def parse_ledger_bytes(data: bytes) -> tuple[list[dict], Optional[dict]]:
    """Strictly parse a ledger file's bytes into records, or return the problem."""
    text = _strict.decode(data)
    if text is None:
        return [], _fail("TAMPERED_LEDGER", "ledger file is not valid UTF-8")
    if _strict.is_legacy_text(text):
        return [], _fail("LEGACY_FORMAT", "this ledger has no `format` field: it was written by auditrail v0.1, "
                         "which the v2 verifier does not judge (it may hold floats and cannot be signed). "
                         "Use --legacy-v01 for a hash-chain-only check.")
    records: list[dict] = []
    for lineno, line in _strict.lines(text):
        try:
            records.append(_strict.parse_object(line))
        except ValueError as exc:
            return records, _fail("TAMPERED_LEDGER", f"record #{len(records)} (line {lineno}) is not an acceptable JSON object: {exc}",
                                  bad_seq=len(records))
    return records, None


def _read_records(path: Path) -> tuple[list[dict], Optional[dict]]:
    if not path.exists():
        return [], None
    return parse_ledger_bytes(path.read_bytes())


def _check_fields(rec: dict, seq: int) -> Optional[dict]:
    """Per-record field rules (spec section 3). Runs after the hash and signature hold."""
    bad = lambda d: _fail("MALFORMED_RECORD", f"seq={seq}: {d}", bad_seq=seq)  # noqa: E731
    if _strict.parse_ts(rec.get("ts")) is None:
        return bad("ts is not a valid UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)")
    kind = rec.get("kind", "call")
    if not isinstance(kind, str):
        return bad("kind is not a string")
    if "policy_hash" in rec and rec["policy_hash"] is not None and not _strict.is_hex(rec["policy_hash"], 64):
        return bad("policy_hash is not 64 lowercase hex characters (or null)")
    if kind == "heartbeat":
        tools = rec.get("tools")
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            return bad("heartbeat tools is not a list of strings")
        if not _strict.is_int(rec.get("calls_attempted")) or not _strict.is_int(rec.get("calls_recorded")):
            return bad("heartbeat call counts are not integers")
    return None


def check_chain(path, public_keys: Optional[dict[str, str]] = None, records: Optional[list[dict]] = None) -> Optional[dict]:
    """Checks 1 and 2 (plus the field rules). Returns None when everything holds.

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
        if not _strict.is_int(rec.get("seq")) or rec["seq"] != expected:
            return _fail("TAMPERED_LEDGER", f"expected seq={expected}, found seq={rec.get('seq')!r}", bad_seq=expected)
        if rec.get("prev_hash") != prev:
            return _fail("TAMPERED_LEDGER", f"seq={expected}: prev_hash does not link to the previous record", bad_seq=expected)
        stored = rec.get("hash")
        if not isinstance(stored, str) or record_hash(prev, rec) != stored:
            return _fail("TAMPERED_LEDGER", f"seq={expected}: hash does not match the record's contents", bad_seq=expected)
        if public_keys is not None:
            key_id, sig = rec.get("key_id"), rec.get("sig")
            if not isinstance(key_id, str) or not key_id or not isinstance(sig, str) or not sig:
                return _fail("UNSIGNED_RECORD", f"seq={expected} carries no signature, but signatures are required", bad_seq=expected)
            pub = public_keys.get(key_id)
            if pub is None:
                return _fail("UNKNOWN_KEY", f"seq={expected} is signed by key_id={key_id}, which is not in the trusted keys", bad_seq=expected)
            if not verify_sig(pub, TAG_RECORD, stored.encode("ascii"), sig):
                return _fail("BAD_SIGNATURE", f"seq={expected}: signature does not verify", bad_seq=expected)
        problem = _check_fields(rec, expected)
        if problem is not None:
            return problem
        prev = stored
    return None


def verify_legacy_v01(path) -> dict:
    """Hash-chain check of a v0.1 ledger, under the v0.1 rules (floats allowed, no signatures).

    This is all v0.1 ever promised, and it is weaker than it sounds: without a key, anyone who can
    write the file can rewrite it and recompute the chain. The report says so."""
    import json

    path = Path(path)
    text = _strict.decode(path.read_bytes())
    if text is None:
        return _fail("TAMPERED_LEDGER", "ledger file is not valid UTF-8")
    records: list[dict] = []
    for lineno, line in _strict.lines(text):
        try:
            rec = json.loads(line, parse_constant=lambda t: (_ for _ in ()).throw(ValueError(t)))
            if not isinstance(rec, dict):
                raise ValueError("not an object")
            rec["hash"].encode("ascii")
        except (ValueError, KeyError, AttributeError, RecursionError):
            return _fail("TAMPERED_LEDGER", f"record #{len(records)} (line {lineno}) is not a v0.1 record", bad_seq=len(records))
        records.append(rec)
    prev = GENESIS_HASH
    for i, rec in enumerate(records):
        if rec.get("seq") != i or rec.get("prev_hash") != prev or record_hash(prev, rec) != rec.get("hash"):
            return _fail("TAMPERED_LEDGER", f"seq={i}: hash chain breaks here", bad_seq=i)
        prev = rec["hash"]
    return {"status": "OK", "detail": f"{len(records)} record(s), legacy v0.1 hash chain intact", "records": len(records),
            "legacy": True, "anchored_upto": None, "unanchored_tail": len(records),
            "notes": ["legacy v0.1 ledger: unsigned, so anyone who could write the file could have rewritten the chain",
                      "no anchors, witness or heartbeats exist for v0.1 ledgers"]}


def _fmt(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def check_heartbeats(records: list[dict], max_gap_s: int) -> tuple[Optional[dict], list[dict]]:
    """Check 5. Returns (problem, changes). Assumes check_chain already passed."""
    beats = [r for r in records if r.get("kind") == "heartbeat"]
    changes: list[dict] = []
    if not beats and records:
        return _fail("NO_HEARTBEAT", "a maximum gap was given but the ledger has no heartbeat records"), changes

    # gaps: first record -> each heartbeat -> last record
    points = [_strict.parse_ts(records[0]["ts"])] if records else []
    points += [_strict.parse_ts(b["ts"]) for b in beats]
    if records:
        points.append(_strict.parse_ts(records[-1]["ts"]))
    gaps = [{"from": _fmt(a), "to": _fmt(b), "seconds": b - a} for a, b in zip(points, points[1:]) if b - a > max_gap_s]

    # every writer reports how many calls it intercepted vs. managed to record
    for b in beats:
        if b["calls_attempted"] != b["calls_recorded"]:
            return _fail("UNRECORDED_CALLS",
                         f"heartbeat seq={b['seq']} from {b.get('recorder_id')!r}: {b['calls_attempted']} call(s) "
                         f"intercepted but only {b['calls_recorded']} recorded", bad_seq=b["seq"]), changes

    prev = None
    for b in beats:
        if prev is not None:
            added = sorted(set(b["tools"]) - set(prev["tools"]))
            removed = sorted(set(prev["tools"]) - set(b["tools"]))
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
    # which policy was in force when: consecutive runs of the same full hash across call records
    policy_hashes: list[dict] = []
    for r in records:
        h = r.get("policy_hash")
        if r.get("kind", "call") != "call" or h is None:
            continue
        if policy_hashes and policy_hashes[-1]["policy_hash"] == h:
            policy_hashes[-1]["last_seq"] = r["seq"]
        else:
            policy_hashes.append({"policy_hash": h, "policy_version": r.get("policy_version"),
                                  "first_seq": r["seq"], "last_seq": r["seq"]})
    base = {"records": len(records), "kinds": kinds, "signatures_checked": public_keys is not None,
            "policy_hashes": policy_hashes}

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
    if len(policy_hashes) > 1:
        notes.append(f"policy changed {len(policy_hashes) - 1} time(s) across call records (see policy_hashes)")
    if max_gap_s is None:
        notes.append("heartbeats NOT checked (no max gap given): silent periods are not detectable")
    detail = f"{len(records)} record(s), chain intact" + (", all signatures valid" if public_keys is not None else "")
    return {"status": "OK", "detail": detail, **base, "anchored_upto": anchored_upto,
            "unanchored_tail": tail, "changes": changes, "notes": notes}
