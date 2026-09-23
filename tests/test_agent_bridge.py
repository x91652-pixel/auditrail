import time

import pytest

from auditrail.agent_bridge import ReplayGuard, SignatureError, sign_message, verify_message

SECRET = "test-secret"


def test_genuine_message_verifies():
    msg = sign_message("agent-a", {"action": "do_thing"}, SECRET)
    payload = verify_message(msg, SECRET)
    assert payload == {"action": "do_thing"}


def test_wrong_secret_rejected():
    msg = sign_message("agent-a", {"action": "do_thing"}, SECRET)
    with pytest.raises(SignatureError):
        verify_message(msg, "wrong-secret")


def test_tampered_payload_rejected():
    msg = sign_message("agent-a", {"amount": 10}, SECRET)
    d = msg.to_dict()
    d["payload"]["amount"] = 10000  # attacker edits after signing
    with pytest.raises(SignatureError):
        verify_message(d, SECRET)


def test_stale_message_rejected():
    msg = sign_message("agent-a", {"x": 1}, SECRET)
    msg.ts = time.time() - 3600  # signed an hour ago
    with pytest.raises(SignatureError):
        verify_message(msg, SECRET, max_age_seconds=60)


def test_replay_rejected_with_guard():
    guard = ReplayGuard()
    msg = sign_message("agent-a", {"x": 1}, SECRET)
    verify_message(msg, SECRET, replay_guard=guard)
    with pytest.raises(SignatureError):
        verify_message(msg, SECRET, replay_guard=guard)


def test_without_replay_guard_same_message_verifies_twice():
    # documents the behavior explicitly: replay protection is opt-in via
    # a ReplayGuard; callers that don't pass one get signature + freshness
    # checks only.
    msg = sign_message("agent-a", {"x": 1}, SECRET)
    assert verify_message(msg, SECRET) == {"x": 1}
    assert verify_message(msg, SECRET) == {"x": 1}
