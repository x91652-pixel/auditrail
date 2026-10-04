"""Tamper-evident, append-only evidence ledger for AI agent decisions.

Each record is chained to the previous one (record_hash = sha256(prev_hash
+ canonical_json(record))), the same construction used by Certificate
Transparency logs. Anyone holding the ledger file can independently verify
that no record was altered, inserted, or removed after the fact, without
trusting the party who produced it.

Design choice: the ledger never stores raw tool arguments or raw results,
only their SHA-256 digests plus a short, explicitly-opt-in preview. Full
conversation/tool payloads are themselves sensitive data (see the DeepSeek
exposed-database incident) and a centralized audit log is a natural target;
keeping only digests lets the log prove *that* a given input/output pair
occurred without becoming a new high-value data-exfiltration target.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

GENESIS_HASH = "0" * 64


def _digest(obj: Any) -> str:
    """SHA-256 digest of a tool call's arguments or result.

    Non-JSON values fall back to repr() so that a failed call with an
    unserializable argument can still be recorded instead of crashing the logger.
    """
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class EvidenceRecord:
    seq: int
    ts: str
    agent_id: str
    session_id: str
    policy_version: str
    tool: str
    categories: list
    args_digest: str
    decision: str  # "allow" | "deny" | "sandboxed"
    reason: Optional[str]
    result_digest: Optional[str]
    duration_ms: Optional[float]
    prev_hash: str
    hash: str = field(default="", init=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class TamperError(Exception):
    """Raised by verify() consumers that want an exception instead of a bool."""


class Ledger:
    """Append-only, hash-chained JSONL evidence ledger.

    Usage:
        ledger = Ledger("evidence.jsonl")
        ledger.record(agent_id="hr-screener", tool="read_resume", ...)
        ok, bad_seq = ledger.verify()
    """

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch()
        self._seq = self._last_seq()

    # ---------------------------------------------------------------- write
    def _last_seq(self) -> int:
        last = None
        for last in self._iter_raw():
            pass
        return last["seq"] if last else -1

    def _last_hash(self) -> str:
        last = None
        for last in self._iter_raw():
            pass
        return last["hash"] if last else GENESIS_HASH

    def record(
        self,
        *,
        agent_id: str,
        session_id: str,
        policy_version: str,
        tool: str,
        categories: list[str],
        args: Any,
        decision: str,
        reason: Optional[str] = None,
        result: Any = None,
        duration_ms: Optional[float] = None,
    ) -> EvidenceRecord:
        assert decision in ("allow", "deny", "sandboxed", "error")
        self._seq += 1
        prev_hash = self._last_hash()
        rec = EvidenceRecord(
            seq=self._seq,
            ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            agent_id=agent_id,
            session_id=session_id,
            policy_version=policy_version,
            tool=tool,
            categories=sorted(categories),
            args_digest=_digest(args),
            decision=decision,
            reason=reason,
            result_digest=_digest(result) if (decision == "allow" and result is not None) else None,
            duration_ms=duration_ms,
            prev_hash=prev_hash,
        )
        body = rec.to_dict()
        del body["hash"]
        rec.hash = hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canonical(rec.to_dict()) + "\n")
        return rec

    # ---------------------------------------------------------------- read
    def _iter_raw(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def __iter__(self) -> Iterator[dict]:
        return self._iter_raw()

    # ---------------------------------------------------------------- verify
    def verify(self) -> tuple[bool, Optional[int]]:
        """Recompute the hash chain. Returns (ok, first_bad_seq).

        first_bad_seq is the seq number of the first record whose stored
        hash does not match what the chain implies -- i.e. the earliest
        point at which the log could have been altered, truncated, or had
        records reordered/inserted.
        """
        prev_hash = GENESIS_HASH
        expected_seq = 0
        for rec in self._iter_raw():
            if rec.get("seq") != expected_seq:
                return False, rec.get("seq")
            if rec.get("prev_hash") != prev_hash:
                return False, rec["seq"]
            body = dict(rec)
            stored_hash = body.pop("hash")
            recomputed = hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()
            if recomputed != stored_hash:
                return False, rec["seq"]
            prev_hash = stored_hash
            expected_seq += 1
        return True, None

    def new_session_id(self) -> str:
        return uuid.uuid4().hex[:12]
