"""F5: the recorder signs only records of a fixed shape, and marks the ones a client asked for with origin="client"."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from auditrail import (Guard, KeyRegistry, Ledger, PolicyEngine, RecorderService, RemoteLedger, ReplayGuard,
                       Signer)
from auditrail.agent_bridge import send_envelope
from auditrail.sandbox import ToolDenied
from auditrail.verifier import verify_all

CONFIG = {
    "version": "stage2",
    "agents": {name: {"allowed_tools": ["read_private", "web"],
                      "tool_categories": {"read_private": ["data_access"], "web": ["untrusted_input"]}}
               for name in ("A", "B")},
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}
GOOD_CALL = {"kind": "call", "agent_id": "a", "session_id": "s", "trace_id": "s", "policy_version": "p",
             "policy_hash": "ab" * 32, "tool": "t", "categories": ["c"], "args_digest": "cd" * 32, "decision": "allow",
             "reason": None, "result_digest": None, "duration_us": 5}
GOOD_HB = {"recorder_id": "r", "tools": ["t"], "policy_version": "p", "policy_hash": "ab" * 32, "calls_attempted": 3,
           "calls_recorded": 3, "interval_s": 60}


def recorder(tmp_path):
    signer = Signer.generate()
    ledger = Ledger(tmp_path / "rec.jsonl", signer=signer, fsync=False)
    return RecorderService(ledger, token="t", heartbeat_s=0).start(), ledger, signer


POISON = {
    "policy_hash": {**GOOD_CALL, "policy_hash": "not-hex!"},
    "args_digest": {**GOOD_CALL, "args_digest": "zz"},
    "categories": {**GOOD_CALL, "categories": "data_access"},
    "duration": {**GOOD_CALL, "duration_us": "5"},
    "extra field": {**GOOD_CALL, "origin": "recorder"},
    "missing field": {k: v for k, v in GOOD_CALL.items() if k != "tool"},
}


@pytest.mark.parametrize("name", sorted(POISON))
def test_a_malformed_call_is_refused_and_not_signed(tmp_path, name):
    svc, ledger, signer = recorder(tmp_path)
    try:
        before = len(list(ledger))
        reply = svc.handle_request({"op": "call", "token": "t", "fields": POISON[name]})
        assert reply["ok"] is False and "refused" in reply["error"]
        assert len(list(ledger)) == before
        assert verify_all(tmp_path / "rec.jsonl", public_keys={signer.key_id: signer.public_hex})["status"] == "OK"
    finally:
        svc.stop()


@pytest.mark.parametrize("bad", [
    {**GOOD_HB, "tools": "every_tool"}, {**GOOD_HB, "calls_attempted": "7"}, {**GOOD_HB, "calls_recorded": True},
    {**GOOD_HB, "calls_attempted": -1}, {**GOOD_HB, "policy_hash": "xyz"}, {**GOOD_HB, "interval_s": 1.5},
    {**GOOD_HB, "surprise": 1}, {k: v for k, v in GOOD_HB.items() if k != "tools"},
])
def test_a_malformed_heartbeat_is_refused(tmp_path, bad):
    svc, ledger, _ = recorder(tmp_path)
    try:
        reply = svc.handle_request({"op": "event", "kind": "heartbeat", "token": "t", "fields": bad})
        assert reply["ok"] is False
        assert [r for r in ledger if r["kind"] == "heartbeat" and r["recorder_id"] != "recorder"] == []
    finally:
        svc.stop()


def test_unknown_kinds_and_non_object_fields_are_refused(tmp_path):
    svc, ledger, _ = recorder(tmp_path)
    try:
        for req in ({"op": "event", "kind": "call", "fields": {}}, {"op": "event", "kind": "x", "fields": {}},
                    {"op": "event", "kind": "heartbeat", "fields": [1]}, {"op": "call", "fields": "no"}):
            assert svc.handle_request({**req, "token": "t"})["ok"] is False
        assert [r for r in ledger if r["kind"] != "heartbeat"] == []
    finally:
        svc.stop()


def test_refused_requests_do_not_count_as_received_calls(tmp_path):
    svc, ledger, _ = recorder(tmp_path)
    try:
        svc.handle_request({"op": "call", "token": "t", "fields": POISON["policy_hash"]})
        assert (svc._received, svc._written) == (0, 0), "a poisoned request must not make the recorder's own heartbeat differ"
    finally:
        svc.stop()


def test_a_well_formed_forged_heartbeat_is_signed_but_marked_as_the_clients(tmp_path):
    svc, ledger, signer = recorder(tmp_path)
    try:
        assert svc.handle_request({"op": "event", "kind": "heartbeat", "token": "t", "fields": GOOD_HB})["ok"] is True
        forged = [r for r in ledger if r["kind"] == "heartbeat" and r["recorder_id"] == "r"][0]
        assert forged["origin"] == "client" and forged["recorder_id"] == "r"
        own = svc.heartbeat()
        assert "origin" not in own, "the recorder's own heartbeat carries no origin"
        keys = {signer.key_id: signer.public_hex}
        assert verify_all(tmp_path / "rec.jsonl", public_keys=keys, max_gap_s=3600)["status"] == "OK"
    finally:
        svc.stop()


def full_flow(tmp_path):
    """Every kind of record the library itself writes, through a real recorder."""
    svc, ledger, signer = recorder(tmp_path)
    a_id, b_id = Signer.generate(), Signer.generate()
    reg = KeyRegistry({"A": a_id.public_hex, "B": b_id.public_hex})
    policy = PolicyEngine(CONFIG)
    port = svc.address[1]
    ga = Guard(policy, RemoteLedger(port=port, token="t"))
    gb = Guard(policy, RemoteLedger(port=port, token="t"))
    sa = ga.session("A")
    ga.guarded_tool("web")(lambda: "page")(sa)
    with pytest.raises(ToolDenied):
        ga.guarded_tool("not_listed")(lambda: 1)(sa)
    with pytest.raises(ZeroDivisionError):
        ga.guarded_tool("read_private")(lambda: 1 / 0)(sa)
    ga.heartbeat()
    env = ga.send_message(sa, a_id, "B", {"task": 1})
    _, _, receipt = gb.receive_message(env, reg, "B", b_id, ReplayGuard())
    ga.accept_receipt(sa, env, receipt, reg)
    forged = send_envelope(a_id, "A", "B", {}, "t")
    forged["payload"] = {"evil": True}
    with pytest.raises(Exception):
        gb.receive_message(forged, reg, "B", b_id, ReplayGuard())
    with pytest.raises(Exception):
        gb.receive_message("not an envelope", reg, "B", b_id, ReplayGuard())  # peer and msg_id are None
    ga.ledger.close()
    gb.ledger.close()
    svc.heartbeat()
    return svc, ledger, signer


def test_every_record_the_library_writes_passes_the_schema_and_verifies(tmp_path):
    svc, ledger, signer = full_flow(tmp_path)
    try:
        recs = list(ledger)
        assert {"call", "heartbeat", "a2a_send", "a2a_recv", "a2a_ack"} <= {r["kind"] for r in recs}
        assert {r["decision"] for r in recs if r["kind"] == "call"} == {"allow", "deny", "error"}
        rejected = [r for r in recs if r["kind"] == "a2a_recv" and r["status"] == "rejected"]
        assert len(rejected) == 2 and any(r["peer"] is None and r["msg_id"] is None for r in rejected)
        for r in recs:
            if r["kind"] != "heartbeat" or r["recorder_id"].startswith("guard-"):
                assert r["origin"] == "client", r["kind"]
        own = [r for r in recs if r["kind"] == "heartbeat" and r["recorder_id"] == "recorder"]
        assert own and all("origin" not in r for r in own)
        assert verify_all(tmp_path / "rec.jsonl", public_keys={signer.key_id: signer.public_hex})["status"] == "OK"
    finally:
        svc.stop()


def test_the_rust_verifier_accepts_a_ledger_with_origin_fields(tmp_path):
    here = Path(__file__).resolve().parents[1]
    candidates = [here / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
    binary = next((p for p in candidates if p.exists()), None) or shutil.which("auditrail-verify")
    if binary is None:
        pytest.skip("Rust verifier not built")
    svc, ledger, signer = full_flow(tmp_path)
    try:
        (tmp_path / "k.pub").write_text(signer.public_hex, encoding="utf-8")
        out = subprocess.run([str(binary), str(tmp_path / "rec.jsonl"), "--pubkey", str(tmp_path / "k.pub"), "--json"],
                             capture_output=True, text=True, encoding="utf-8")
        assert json.loads(out.stdout)["status"] == "OK", out.stdout
    finally:
        svc.stop()
