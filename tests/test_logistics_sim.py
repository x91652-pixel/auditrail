"""End-to-end: the simulated logistics company under normal operation and attack.

Each attack declares its expected outcome. Known gaps are asserted to NOT be
stopped, so the suite documents the limitations instead of hiding them.
"""
import pytest

from examples.logistics_sim.scenarios import run_simulation


@pytest.fixture(scope="module")
def sim(tmp_path_factory):
    path = tmp_path_factory.mktemp("sim") / "ledger.jsonl"
    return run_simulation(path)


def test_no_false_positives_in_normal_operations(sim):
    blocked = [r.name for r in sim["legit"] if r.actual != "ALLOWED"]
    assert blocked == [], f"legitimate operations were blocked: {blocked}"


def test_every_attack_matches_its_declared_expectation(sim):
    mismatched = [(r.name, r.expected, r.actual, r.detail) for r in sim["attacks"] if not r.passed]
    assert mismatched == []


def test_injection_driven_exfiltration_is_blocked_before_sending(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Indirect prompt injection"))
    assert r.actual == "BLOCKED"
    assert "lethal_trifecta" in r.detail


def test_malicious_carrier_payload_cannot_email_out(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Malicious carrier payload → shipment list"))
    assert r.actual == "BLOCKED"


def test_forged_refund_approval_is_rejected(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Forged agent message"))
    assert r.actual == "BLOCKED"
    assert "signature mismatch" in r.detail


def test_replay_is_rejected_but_first_delivery_was_legitimate(sim):
    r = next(a for a in sim["attacks"] if a.name == "Replayed approval message")
    assert r.actual == "BLOCKED"
    assert "first delivery: ALLOWED" in r.detail


def test_sandboxed_tool_cannot_read_planted_api_key(sim):
    r = next(a for a in sim["attacks"] if a.name == "Secret theft from a sandboxed tool")
    assert r.actual == "CONTAINED"
    assert "sk-live-SIMULATED" not in r.detail


def test_hung_tool_is_contained_by_timeout(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Runaway"))
    assert r.actual == "CONTAINED"


def test_known_gap_write_action_without_external_channel_is_not_blocked(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Malicious carrier payload → shipment rerouted"))
    assert r.actual == "ALLOWED"
    assert r.known_gap


def test_known_gap_trifecta_split_across_sessions_is_not_blocked(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Trifecta split"))
    assert r.actual == "ALLOWED"
    assert r.known_gap


def test_tampering_with_recorded_decision_is_detected(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Evidence tampering: deny rewritten"))
    assert r.actual == "DETECTED"


def test_tail_truncation_is_a_documented_undetected_gap(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Evidence tampering: last record"))
    assert r.actual == "NOT DETECTED"
    assert r.known_gap


def test_live_ledger_chain_is_intact_and_records_failures(sim):
    assert sim["ledger_ok"] is True
    # blocked calls and sandbox errors are evidence too, not silently dropped
    assert sim["decisions"]["deny"] >= 3
    assert sim["decisions"]["error"] >= 4
    assert sim["decisions"]["sandboxed"] >= 2


def test_only_intended_messages_left_the_company(sim):
    # 1 dispatch notify + 2 legit support replies + 1 split-session leak (known gap)
    assert sim["outbox_count"] == 4


def test_routing_changes_include_the_unblocked_malicious_reroute(sim):
    assert ("SHP-666", "TXG-HUB-EVIL") in sim["routing_changes"]


def test_each_run_starts_from_clean_state(tmp_path):
    first = run_simulation(tmp_path / "a.jsonl")
    second = run_simulation(tmp_path / "b.jsonl")
    assert [r.actual for r in first["attacks"]] == [r.actual for r in second["attacks"]]
    assert first["outbox_count"] == second["outbox_count"] == 4


def test_v02_trifecta_split_across_agents_is_blocked_as_one_workflow(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Trifecta split across two agents"))
    assert r.actual == "BLOCKED"
    assert "workflow" in r.detail and "inherited" in r.detail
    assert sim["outbox_count"] == 4


def test_v02_rewrite_with_recomputed_hashes_is_caught_by_the_recorder_signature(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Evidence tampering: deny rewritten AND every hash"))
    assert r.actual == "DETECTED"
    assert "chain alone passes=True" in r.detail and "BAD_SIGNATURE" in r.detail


def test_v02_truncation_after_a_witnessed_anchor_is_caught(sim):
    r = next(a for a in sim["attacks"] if a.name.startswith("Evidence tampering: tail deleted after a witnessed anchor"))
    assert r.actual == "DETECTED" and "TRUNCATED" in r.detail


def test_v02_simulation_ledger_verifies_with_signatures_anchors_and_witness(sim):
    from auditrail.anchor import FileSink
    from auditrail.verifier import verify_all

    res = verify_all(sim["ledger_path"], public_keys=sim["public_keys"], anchors_path=sim["anchors_path"],
                     sinks={"file": FileSink(sim["witness_path"])}, witness_path=sim["witness_path"])
    assert res["status"] == "OK" and res["unanchored_tail"] == 0
