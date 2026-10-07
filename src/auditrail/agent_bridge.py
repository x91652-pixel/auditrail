"""Signed envelopes for agent-to-agent messages (OWASP ASI07).

When one agent invokes another agent as a "tool" (a sub-agent, a
specialist agent, an MCP-connected peer agent), the receiving agent
normally has no way to tell a legitimate call from the calling agent
apart from a spoofed message injected by a compromised tool or a
malicious peer on the same bus. That gap is OWASP's "Insecure Inter-Agent
Communication" (ASI07:2026).

Two schemes live here.

v2 (recommended): send_envelope / receive_envelope / make_receipt.
  Each agent has its own Ed25519 key, so a signature says WHICH agent sent a
  message and can be shown to a third party. The envelope names its
  recipient, carries the workflow trace_id and the sender's trifecta
  categories (so the receiver's policy inherits them), and the receiver
  answers with a signed receipt. Both sides write the message digest to their
  own ledgers; reconcile.py then finds messages only one side recorded.
  Replay protection is mandatory.

v1 (legacy, kept for compatibility): sign_message / verify_message.
  An HMAC-SHA256 signature over (sender_id, timestamp, nonce, payload), plus a
  freshness window and optional nonce tracking. Both sides share one secret, so
  anyone holding it can sign as ANY sender: it proves "someone inside the trust
  domain", not who. Prefer v2 for anything that may need attribution.

Signatures prove where a message came from. They do not prove its content is
safe: an injected instruction can travel inside a correctly signed message.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from .keys import TAG_A2A, TAG_RECEIPT, KeyRegistry, Signer, key_id_for, verify_sig


class SignatureError(ValueError):
    pass


class ReplayGuard:
    """In-memory nonce tracker. For multi-process deployments, back this
    with a shared store (Redis, a DB table with a unique index) instead --
    tracked in ROADMAP.md.

    Nonces older than ttl_seconds are forgotten, which keeps memory bounded.
    That is safe while ttl_seconds >= the receiver's max message age plus clock
    skew: an older message is rejected by the freshness check anyway.
    """

    def __init__(self, ttl_seconds: float = 300.0):
        self.ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}

    def seen_before(self, nonce: str) -> bool:
        now = time.monotonic()
        if len(self._seen) > 1024:
            cutoff = now - self.ttl_seconds
            self._seen = {n: t for n, t in self._seen.items() if t >= cutoff}
        if nonce in self._seen:
            return True
        self._seen[nonce] = now
        return False


# ====================================================================== v1 (legacy HMAC)

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


# ====================================================================== v2 (Ed25519, per agent)

ENVELOPE_VERSION = 2
_ENVELOPE_BODY = ("v", "msg_id", "sender", "recipient", "ts_ms", "trace_id", "categories", "payload", "key_id")
_RECEIPT_BODY = ("v", "msg_digest", "recipient", "received_ms", "key_id")


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def message_digest(envelope: dict) -> str:
    """sha256 over the whole signed envelope: the id both ledgers record."""
    return hashlib.sha256(_canon(envelope)).hexdigest()


def send_envelope(identity: Signer, sender: str, recipient: str, payload: Any, trace_id: str, categories=()) -> dict:
    """Build a signed v2 envelope.

    categories should be the sender workflow's categories (PolicyEngine.seen(session))
    so the receiver's policy inherits them. Floats are not allowed in the payload
    (same canonical-JSON rule as the ledger); encode them as strings or integers.
    """
    body = {
        "v": ENVELOPE_VERSION,
        "msg_id": uuid.uuid4().hex,
        "sender": sender,
        "recipient": recipient,
        "ts_ms": int(time.time() * 1000),
        "trace_id": trace_id,
        "categories": sorted(set(categories)),
        "payload": payload,
        "key_id": identity.key_id,
    }
    return {**body, "sig": identity.sign(TAG_A2A, _canon(body))}


@dataclass
class Delivered:
    sender: str
    recipient: str
    payload: Any
    trace_id: str
    categories: list
    msg_id: str
    msg_digest: str
    sender_sig: str


def receive_envelope(
    envelope: dict,
    registry: KeyRegistry,
    recipient: str,
    replay_guard: ReplayGuard,
    max_age_seconds: float = 60.0,
) -> Delivered:
    """Verify a v2 envelope addressed to `recipient`. Raises SignatureError on any problem."""
    if replay_guard is None:
        raise ValueError("replay_guard is required for v2 envelopes")
    if not isinstance(envelope, dict) or envelope.get("v") != ENVELOPE_VERSION:
        raise SignatureError("not a v2 agent envelope")
    missing = [k for k in (*_ENVELOPE_BODY, "sig") if k not in envelope]
    if missing:
        raise SignatureError(f"malformed envelope (missing {missing})")
    if set(envelope) - set(_ENVELOPE_BODY) - {"sig"}:
        raise SignatureError("malformed envelope (unexpected fields)")

    sender = envelope["sender"]
    pub = registry.public_key(sender)
    if pub is None:
        raise SignatureError(f"unknown sender '{sender}' -- no public key registered")
    if envelope["key_id"] != key_id_for(pub):
        raise SignatureError(f"message claims sender '{sender}' but names another key -- possible spoofed agent message")
    body = {k: envelope[k] for k in _ENVELOPE_BODY}
    if not verify_sig(pub, TAG_A2A, _canon(body), envelope["sig"]):
        raise SignatureError(f"signature mismatch for message from '{sender}' -- possible spoofed agent message")
    if envelope["recipient"] != recipient:
        raise SignatureError(f"message is addressed to '{envelope['recipient']}', not '{recipient}' -- possible redirected message")

    age = time.time() - envelope["ts_ms"] / 1000.0
    if age > max_age_seconds or age < -5:
        raise SignatureError(f"message from '{sender}' is {age:.1f}s old (max {max_age_seconds}s) -- possible replay")
    if replay_guard.seen_before(envelope["msg_id"]):
        raise SignatureError(f"msg_id already used for a message from '{sender}' -- replay detected")

    return Delivered(
        sender=sender, recipient=recipient, payload=envelope["payload"], trace_id=envelope["trace_id"],
        categories=list(envelope["categories"]), msg_id=envelope["msg_id"],
        msg_digest=message_digest(envelope), sender_sig=envelope["sig"],
    )


def make_receipt(identity: Signer, delivered: Delivered) -> dict:
    """The receiver's signed statement: "I, recipient, received message msg_digest"."""
    body = {"v": ENVELOPE_VERSION, "msg_digest": delivered.msg_digest, "recipient": delivered.recipient,
            "received_ms": int(time.time() * 1000), "key_id": identity.key_id}
    return {**body, "sig": identity.sign(TAG_RECEIPT, _canon(body))}


def verify_receipt(receipt: dict, registry: KeyRegistry, expected_digest: str, expected_recipient: str) -> None:
    """Check a receipt came from the intended recipient for this exact message. Raises SignatureError."""
    body = {k: receipt.get(k) for k in _RECEIPT_BODY}
    if body["msg_digest"] != expected_digest or body["recipient"] != expected_recipient:
        raise SignatureError("receipt is for a different message or recipient")
    pub = registry.public_key(expected_recipient)
    if pub is None or body["key_id"] != key_id_for(pub):
        raise SignatureError(f"no trusted key for receipt from '{expected_recipient}'")
    if not verify_sig(pub, TAG_RECEIPT, _canon(body), receipt.get("sig", "")):
        raise SignatureError(f"receipt signature from '{expected_recipient}' does not verify")
