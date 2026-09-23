"""Signed envelopes for agent-to-agent messages (OWASP ASI07).

When one agent invokes another agent as a "tool" (a sub-agent, a
specialist agent, an MCP-connected peer agent), the receiving agent
normally has no way to tell a legitimate call from the calling agent
apart from a spoofed message injected by a compromised tool or a
malicious peer on the same bus. That gap is OWASP's "Insecure Inter-Agent
Communication" (ASI07:2026).

This module gives every inter-agent message an HMAC-SHA256 signature over
(sender_id, timestamp, nonce, payload), plus replay protection (a
timestamp freshness window and a seen-nonce set). It does not attempt key
distribution / rotation -- for the MVP, both sides share a secret out of
band (env var, secrets manager, etc.); a public-key scheme is tracked in
ROADMAP.md for cross-organization agent calls.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional


class SignatureError(ValueError):
    pass


@dataclass
class AgentMessage:
    sender: str
    ts: float
    nonce: str
    payload: Any
    sig: str

    def to_dict(self) -> dict:
        return {"sender": self.sender, "ts": self.ts, "nonce": self.nonce, "payload": self.payload, "sig": self.sig}


def _mac(secret: str, sender: str, ts: float, nonce: str, payload: Any) -> str:
    body = json.dumps({"sender": sender, "ts": ts, "nonce": nonce, "payload": payload}, sort_keys=True, ensure_ascii=False)
    return hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_message(sender: str, payload: Any, secret: str) -> AgentMessage:
    ts = time.time()
    nonce = uuid.uuid4().hex
    sig = _mac(secret, sender, ts, nonce, payload)
    return AgentMessage(sender=sender, ts=ts, nonce=nonce, payload=payload, sig=sig)


class ReplayGuard:
    """In-memory nonce tracker. For multi-process deployments, back this
    with a shared store (Redis, a DB table with a unique index) instead --
    tracked in ROADMAP.md."""

    def __init__(self):
        self._seen: set[str] = set()

    def seen_before(self, nonce: str) -> bool:
        if nonce in self._seen:
            return True
        self._seen.add(nonce)
        return False


def verify_message(
    msg: AgentMessage | dict,
    secret: str,
    replay_guard: Optional[ReplayGuard] = None,
    max_age_seconds: float = 60.0,
) -> Any:
    """Returns the verified payload, or raises SignatureError."""
    if isinstance(msg, dict):
        msg = AgentMessage(**msg)

    expected = _mac(secret, msg.sender, msg.ts, msg.nonce, msg.payload)
    if not hmac.compare_digest(expected, msg.sig):
        raise SignatureError(f"signature mismatch for message from '{msg.sender}' -- possible spoofed agent message")

    age = time.time() - msg.ts
    if age > max_age_seconds or age < -5:
        raise SignatureError(f"message from '{msg.sender}' is {age:.1f}s old (max {max_age_seconds}s) -- possible replay")

    if replay_guard is not None and replay_guard.seen_before(msg.nonce):
        raise SignatureError(f"nonce already used for a message from '{msg.sender}' -- replay detected")

    return msg.payload
