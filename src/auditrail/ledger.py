"""Append-only, hash-chained evidence ledger for AI agent decisions.

Each record is chained to the previous one: hash = sha256(prev_hash +
canonical_json(record without hash/sig)), the construction Certificate
Transparency logs use. The full format is specified in
docs/spec/evidence-format-v2.md, so a verifier can be written in any language
(verifier/ is an independent one in Rust).

What the chain alone proves, and what it does not:
  * Without a signing key, anyone who can write the file can edit a record and
    recompute every hash after it. The chain then only catches careless edits.
  * With a signer (a recorder key the agent never sees), every record carries an
    Ed25519 signature, so a rewrite also needs that key.
  * Neither proves that nothing was cut off the end. That needs anchors published
    to a witness (anchor.py) and heartbeats (record_heartbeat) so gaps show.

Design choice: the ledger never stores raw tool arguments or results, only their
SHA-256 digests. Full payloads are sensitive data in their own right, and a
central audit log is a natural target; digests prove *that* a given input/output
occurred without turning the log into a new exfiltration target.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from .keys import TAG_RECORD, Signer, verify_sig

GENESIS_HASH = "0" * 64
FORMAT_VERSION = 2
DECISIONS = ("allow", "deny", "sandboxed", "error")
EVENT_KINDS = ("heartbeat", "a2a_send", "a2a_recv", "a2a_ack")


def _digest(obj: Any) -> str:
    """SHA-256 digest of a tool call's arguments or result.

    Non-JSON values fall back to repr() so that a failed call with an
    unserializable argument can still be recorded instead of crashing the logger.
    """
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _check_no_floats(obj: Any) -> None:
    """v2 records contain no floats, so every verifier can reproduce the canonical bytes."""
    if isinstance(obj, float):
        raise TypeError("format v2 records must not contain floats (use integers)")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_no_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_no_floats(v)


def record_hash(prev_hash: str, record: dict) -> str:
    """Hash of a record as stored: everything except `hash` and `sig`."""
    body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


class InvalidRecord(AssertionError, ValueError):
    """A record the ledger refuses to write (for example an unknown decision value)."""


CALL_FIELDS = ("kind", "agent_id", "session_id", "trace_id", "policy_version", "tool", "categories",
               "args_digest", "decision", "reason", "result_digest", "duration_us")


def call_fields(
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
    trace_id: Optional[str] = None,
) -> dict:
    """The fields of one call record, with arguments and result reduced to digests."""
    if decision not in DECISIONS:
        raise InvalidRecord(f"decision must be one of {DECISIONS}, got {decision!r}")
    has_result = decision in ("allow", "sandboxed") and result is not None
    return {
        "kind": "call",
        "agent_id": agent_id,
        "session_id": session_id,
        "trace_id": trace_id or session_id,
        "policy_version": policy_version,
        "tool": tool,
        "categories": sorted(categories),
        "args_digest": _digest(args),
        "decision": decision,
        "reason": reason,
        "result_digest": _digest(result) if has_result else None,
        "duration_us": None if duration_ms is None else int(round(duration_ms * 1000)),
    }


class EvidenceRecord(dict):
    """A written record. A dict, with attribute access for convenience (rec.seq, rec.hash)."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def to_dict(self) -> dict:
        return dict(self)


class TamperError(Exception):
    """Raised by verify() consumers that want an exception instead of a bool."""


def _utc_ts(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


@contextlib.contextmanager
def _file_lock(lock_path: Path):
    """Exclusive cross-process lock, so two writers never produce the same seq."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+b") as fh:
        if os.name == "nt":
            import msvcrt

            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:  # LK_LOCK gives up after ~10s; keep waiting
                    continue
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _last_line(path: Path) -> Optional[str]:
    """Return the last non-blank line without reading the whole file."""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        buf = b""
        pos = end
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            stripped = buf.rstrip(b"\r\n \t")
            nl = stripped.rfind(b"\n")
            if nl != -1:
                return stripped[nl + 1:].decode("utf-8")
        stripped = buf.strip()
        return stripped.decode("utf-8") if stripped else None


class Ledger:
    """Append-only, hash-chained JSONL evidence ledger.

    Usage:
        ledger = Ledger("evidence.jsonl", signer=Signer.from_file("recorder.key"))
        ledger.record(agent_id="hr-screener", tool="read_resume", ...)
        ok, bad_seq = ledger.verify()

    signer: when given, every record gets key_id + an Ed25519 signature. Only give
    a signer to a ledger running in a process the agent cannot read (see recorder.py).
    clock: returns epoch seconds; injectable for deterministic test vectors.
    """

    def __init__(
        self,
        path: str | os.PathLike,
        signer: Optional[Signer] = None,
        clock: Callable[[], float] = time.time,
        fsync: bool = True,
    ):
        self.path = Path(path)
        self.signer = signer
        self.clock = clock
        self.fsync = fsync
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch()
        self._lock_path = self.path.with_name(self.path.name + ".lock")

    # ---------------------------------------------------------------- write
    def _head(self) -> tuple[int, str]:
        last = _last_line(self.path)
        if last is None:
            return -1, GENESIS_HASH
        rec = json.loads(last)
        return rec["seq"], rec["hash"]

    def _append(self, fields: dict) -> EvidenceRecord:
        _check_no_floats(fields)
        with _file_lock(self._lock_path):
            last_seq, prev_hash = self._head()
            rec = {
                "format": FORMAT_VERSION,
                "seq": last_seq + 1,
                "ts": _utc_ts(self.clock()),
                **fields,
                "prev_hash": prev_hash,
            }
            if self.signer is not None:
                rec["key_id"] = self.signer.key_id
            rec["hash"] = record_hash(prev_hash, rec)
            if self.signer is not None:
                rec["sig"] = self.signer.sign(TAG_RECORD, rec["hash"].encode("ascii"))
            with self.path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(_canonical(rec) + "\n")
                f.flush()
                if self.fsync:
                    os.fsync(f.fileno())
        return EvidenceRecord(rec)

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
        trace_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Record one tool-call decision. duration_ms is stored as integer microseconds."""
        return self.append_call(call_fields(
            agent_id=agent_id, session_id=session_id, policy_version=policy_version, tool=tool,
            categories=categories, args=args, decision=decision, reason=reason, result=result,
            duration_ms=duration_ms, trace_id=trace_id,
        ))

    def append_call(self, fields: dict) -> EvidenceRecord:
        """Write call fields prepared by call_fields() (digests already computed).

        This is what the recorder service uses: the agent side computes digests,
        so raw arguments and results never leave the agent process.
        """
        if set(fields) != set(CALL_FIELDS):
            raise InvalidRecord(f"call fields must be exactly {sorted(CALL_FIELDS)}")
        if fields["kind"] != "call" or fields["decision"] not in DECISIONS:
            raise InvalidRecord(f"decision must be one of {DECISIONS}, got {fields['decision']!r}")
        return self._append(dict(fields))

    def record_event(self, kind: str, **fields: Any) -> EvidenceRecord:
        """Record a non-call event: a heartbeat or one side of an agent-to-agent message."""
        if kind not in EVENT_KINDS:
            raise InvalidRecord(f"kind must be one of {EVENT_KINDS}, got {kind!r}")
        reserved = {"format", "seq", "ts", "kind", "prev_hash", "hash", "sig", "key_id"} & set(fields)
        if reserved:
            raise InvalidRecord(f"fields {sorted(reserved)} are set by the ledger itself")
        return self._append({"kind": kind, **fields})

    def record_heartbeat(
        self,
        *,
        recorder_id: str,
        tools: list[str],
        policy_version: str,
        policy_hash: str,
        calls_attempted: int,
        calls_recorded: int,
        interval_s: int,
    ) -> EvidenceRecord:
        """A periodic "still recording" marker from one writer (recorder_id).

        calls_attempted / calls_recorded count, since this writer's previous
        heartbeat, the tool calls it intercepted and the ones it managed to write.
        A difference means calls ran without evidence. A gap between heartbeats
        longer than expected is visible to the verifier as a period with no coverage."""
        return self.record_event(
            "heartbeat",
            recorder_id=recorder_id,
            tools=sorted(tools),
            policy_version=policy_version,
            policy_hash=policy_hash,
            calls_attempted=calls_attempted,
            calls_recorded=calls_recorded,
            interval_s=interval_s,
        )

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
    def verify(self, public_keys: Optional[dict[str, str]] = None) -> tuple[bool, Optional[int]]:
        """Recompute the hash chain. Returns (ok, first_bad_seq).

        first_bad_seq is the position of the first record that does not match
        what the chain implies: altered, inserted, reordered, malformed, or (when
        public_keys {key_id: public_hex} is given) carrying a missing or invalid
        signature. It cannot see records cut off the end; see anchor.py.
        For a full report (signatures, anchors, heartbeat gaps) use verifier.verify_all.
        """
        from .verifier import check_chain

        problem = check_chain(self.path, public_keys=public_keys)
        if problem is None:
            return True, None
        return False, problem["bad_seq"]

    def new_session_id(self) -> str:
        return uuid.uuid4().hex[:12]
