"""What the recorder is willing to sign for a client.

A client that holds the recorder token chooses the fields of the records it asks for. The recorder signs whatever it is
given, so without these checks a client could have a record signed that the verifier then rejects as malformed
(stopping verification at that record), or one that reads like the recorder's own heartbeat. Each kind of record has an
exact set of fields and a type for each; anything else is refused and nothing is signed or written.

This is a check of shape, not of truth: the recorder cannot see inside the agent, so a well-formed statement that is
false (a wrong decision, a made-up heartbeat count) is still signed. Such a record carries `origin: "client"`.
"""
from __future__ import annotations

from typing import Any

from ._strict import is_hex

MAX_TEXT = 1024
MAX_REASON = 8192
MAX_LIST = 1024
MAX_INT = 2**63 - 1
DECISIONS = ("allow", "deny", "sandboxed", "error")


class RecordRejected(ValueError):
    """The request does not have the shape the recorder signs."""


def _text(v: Any, limit: int = MAX_TEXT) -> bool:
    return isinstance(v, str) and len(v) <= limit


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_INT


def _hex64(v: Any) -> bool:
    return isinstance(v, str) and is_hex(v, 64)


def _strs(v: Any) -> bool:
    return isinstance(v, list) and len(v) <= MAX_LIST and all(_text(x) for x in v)


def _opt(check):
    return lambda v: v is None or check(v)


def _reason(v: Any) -> bool:
    return _text(v, MAX_REASON)


_CALL = {
    "kind": lambda v: v == "call", "agent_id": _text, "session_id": _text, "trace_id": _text, "policy_version": _text,
    "policy_hash": _opt(_hex64), "tool": _text, "categories": _strs, "args_digest": _hex64,
    "decision": lambda v: v in DECISIONS, "reason": _opt(_reason), "result_digest": _opt(_hex64),
    "duration_us": _opt(_int),
}

# kind -> list of allowed field sets, each {field: check}. The first set that matches exactly is used.
_EVENTS = {
    "heartbeat": [{
        "recorder_id": _text, "tools": _strs, "policy_version": _text, "policy_hash": _opt(_hex64),
        "calls_attempted": _int, "calls_recorded": _int, "interval_s": _int,
    }],
    "a2a_send": [{
        "agent_id": _text, "session_id": _text, "trace_id": _text, "peer": _text, "msg_id": _text,
        "msg_digest": _hex64, "categories": _strs,
    }],
    "a2a_recv": [
        {"agent_id": _text, "status": lambda v: v == "accepted", "session_id": _text, "trace_id": _text,
         "peer": _text, "msg_id": _text, "msg_digest": _hex64, "categories": _strs, "sender_sig": _text,
         "receipt_sig": _text},
        {"agent_id": _text, "status": lambda v: v == "rejected", "reason": _reason, "peer": _opt(_text),
         "msg_id": _opt(_text)},
    ],
    "a2a_ack": [{
        "agent_id": _text, "session_id": _text, "trace_id": _text, "peer": _text, "msg_id": _text,
        "msg_digest": _hex64, "receipt_sig": _text,
    }],
}


def _match(fields: Any, spec: dict) -> str:
    """'' if `fields` fits `spec` exactly, else why not."""
    if not isinstance(fields, dict):
        return "fields must be an object"
    missing = sorted(set(spec) - set(fields))
    extra = sorted(set(fields) - set(spec))
    if missing or extra:
        return f"missing {missing}, unexpected {extra}"
    bad = sorted(k for k, check in spec.items() if not check(fields[k]))
    return f"wrong type or format for {bad}" if bad else ""


def check_call(fields: Any) -> None:
    why = _match(fields, _CALL)
    if why:
        raise RecordRejected(f"call record refused ({why})")


def check_event(kind: Any, fields: Any) -> None:
    specs = _EVENTS.get(kind) if isinstance(kind, str) else None
    if specs is None:
        raise RecordRejected(f"event kind {kind!r} refused")
    reasons = []
    for spec in specs:
        why = _match(fields, spec)
        if not why:
            return
        reasons.append(why)
    raise RecordRejected(f"{kind} record refused ({'; '.join(reasons)})")
