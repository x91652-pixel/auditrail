import json

from auditrail.ledger import GENESIS_HASH, Ledger


def test_record_and_verify(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    ledger.record(
        agent_id="a1", session_id="s1", policy_version="v1", tool="read_x",
        categories=["data_access"], args={"id": 1}, decision="allow", result={"ok": True},
    )
    ledger.record(
        agent_id="a1", session_id="s1", policy_version="v1", tool="write_y",
        categories=["external_comm"], args={"id": 1}, decision="allow", result={"ok": True},
    )
    ok, bad = ledger.verify()
    assert ok is True
    assert bad is None
    assert sum(1 for _ in ledger) == 2


def test_first_record_chains_to_genesis(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    rec = ledger.record(
        agent_id="a1", session_id="s1", policy_version="v1", tool="t",
        categories=[], args={}, decision="allow",
    )
    assert rec.prev_hash == GENESIS_HASH
    assert rec.seq == 0


def test_tamper_in_middle_is_detected(tmp_path):
    path = tmp_path / "l.jsonl"
    ledger = Ledger(path)
    for i in range(5):
        ledger.record(
            agent_id="a1", session_id="s1", policy_version="v1", tool=f"t{i}",
            categories=[], args={"i": i}, decision="allow", result={"i": i},
        )
    ok, bad = ledger.verify()
    assert ok is True

    lines = path.read_text(encoding="utf-8").splitlines()
    victim = json.loads(lines[2])
    victim["decision"] = "deny"  # flip a field without recomputing the hash
    lines[2] = json.dumps(victim, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ledger2 = Ledger(path)
    ok2, bad2 = ledger2.verify()
    assert ok2 is False
    assert bad2 == 2


def test_truncating_the_tail_is_not_silently_accepted_as_more_records(tmp_path):
    path = tmp_path / "l.jsonl"
    ledger = Ledger(path)
    for i in range(3):
        ledger.record(
            agent_id="a1", session_id="s1", policy_version="v1", tool=f"t{i}",
            categories=[], args={}, decision="allow", result={},
        )
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")  # drop the last record

    ledger2 = Ledger(path)
    ok, bad = ledger2.verify()
    # A silent truncation still leaves a *shorter but internally consistent*
    # chain -- verify() proves "nothing in this file was altered", not
    # "nothing was ever removed from the end". That's why redundant,
    # independent custody of the ledger (e.g. append-only storage, periodic
    # export) matters; see SECURITY.md.
    assert ok is True
    assert sum(1 for _ in ledger2) == 2


def test_args_and_results_are_never_stored_in_plaintext(tmp_path):
    path = tmp_path / "l.jsonl"
    ledger = Ledger(path)
    secret_arg = {"ssn": "123-45-6789", "resume_text": "very private content"}
    ledger.record(
        agent_id="a1", session_id="s1", policy_version="v1", tool="t",
        categories=["data_access"], args=secret_arg, decision="allow", result={"score": 90},
    )
    raw = path.read_text(encoding="utf-8")
    assert "123-45-6789" not in raw
    assert "very private content" not in raw
