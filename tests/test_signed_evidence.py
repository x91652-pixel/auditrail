"""v0.2: signatures, signed anchors, witness copies, heartbeats.

The headline case: in v0.1, anyone who could write the ledger file could edit
a record and recompute every hash after it, and verify() still passed. With a
recorder key the agent never sees, that rewrite now fails verification.
"""
import json
import multiprocessing as mp

import pytest

from auditrail.anchor import FileSink, anchor_ledger
from auditrail.keys import Signer, load_public_keys
from auditrail.ledger import GENESIS_HASH, Ledger, _canonical, record_hash
from auditrail.verifier import verify_all

SEED = bytes(range(32))


def _signer():
    return Signer.from_seed(SEED)


def _keys(signer):
    return {signer.key_id: signer.public_hex}


def _fill(ledger, n=5):
    for i in range(n):
        ledger.record(agent_id="a", session_id="s", policy_version="v1", tool=f"t{i}",
                      categories=[], args={"i": i}, decision="deny" if i == 2 else "allow", result={"i": i})


def _rewrite_and_rehash(path, seq, **changes):
    """The attack from the v0.1 review: edit one record, then recompute every hash after it."""
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    recs[seq].update(changes)
    prev = GENESIS_HASH
    for r in recs:
        r["prev_hash"] = prev
        r["hash"] = record_hash(prev, r)
        prev = r["hash"]
    path.write_text("".join(_canonical(r) + "\n" for r in recs), encoding="utf-8")


def test_rewrite_and_rehash_passes_without_keys_but_fails_with_signatures(tmp_path):
    signer = _signer()
    path = tmp_path / "l.jsonl"
    _fill(Ledger(path, signer=signer))
    _rewrite_and_rehash(path, 2, decision="allow", reason=None)

    # the honest v0.1 limitation, still true when no key is checked
    assert Ledger(path).verify() == (True, None)
    # with the recorder's public key, the rewrite is caught at the first edited record
    ok, bad = Ledger(path).verify(public_keys=_keys(signer))
    assert ok is False and bad == 2
    assert verify_all(path, public_keys=_keys(signer))["status"] == "BAD_SIGNATURE"


def test_stripping_signatures_does_not_help_the_attacker(tmp_path):
    signer = _signer()
    path = tmp_path / "l.jsonl"
    _fill(Ledger(path, signer=signer))
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    for r in recs:
        r.pop("sig"); r.pop("key_id")
    prev = GENESIS_HASH
    for r in recs:
        r["prev_hash"] = prev
        r["hash"] = record_hash(prev, r)
        prev = r["hash"]
    path.write_text("".join(_canonical(r) + "\n" for r in recs), encoding="utf-8")
    r = verify_all(path, public_keys=_keys(signer))
    assert r["status"] == "UNSIGNED_RECORD" and r["bad_seq"] == 0


def test_a_different_key_is_rejected(tmp_path):
    path = tmp_path / "l.jsonl"
    _fill(Ledger(path, signer=Signer.generate()))  # attacker's own key
    r = verify_all(path, public_keys=_keys(_signer()))
    assert r["status"] == "UNKNOWN_KEY"


def test_signed_ledger_verifies_and_reports_what_is_not_covered(tmp_path):
    signer = _signer()
    path = tmp_path / "l.jsonl"
    _fill(Ledger(path, signer=signer))
    r = verify_all(path, public_keys=_keys(signer))
    assert r["status"] == "OK" and r["signatures_checked"] is True
    assert any("truncation" in n for n in r["notes"])  # no anchors given: says so out loud


def test_keygen_files_round_trip(tmp_path):
    s = Signer.generate()
    key_path, pub_path = s.save(tmp_path / "rec")
    assert Signer.from_file(key_path).key_id == s.key_id
    assert load_public_keys([pub_path]) == {s.key_id: s.public_hex}
    with pytest.raises(FileExistsError):
        s.save(tmp_path / "rec")  # never overwrite a private key


# ------------------------------------------------------------------ anchors + witness

def test_signed_anchor_in_witness_catches_whole_chain_rewrite_even_with_owner_anchors_deleted(tmp_path):
    signer = _signer()
    path, anchors, witness = tmp_path / "l.jsonl", tmp_path / "anchors.jsonl", tmp_path / "witness.jsonl"
    led = Ledger(path, signer=signer)
    _fill(led)
    anchor_ledger(led, anchors, sink=FileSink(witness), signer=signer)

    # owner rebuilds the ledger from scratch (new key, so signatures "verify" for that key) and drops anchors
    attacker = Signer.generate()
    path.unlink(); anchors.unlink()
    led2 = Ledger(path, signer=attacker)
    _fill(led2)
    # a third party who kept the witness copy and trusts only the real recorder key:
    r = verify_all(path, public_keys=_keys(signer), witness_path=witness)
    assert r["status"] in ("UNKNOWN_KEY", "REWRITTEN")
    # even trusting both keys, the published head no longer matches
    r = verify_all(path, public_keys={**_keys(signer), **_keys(attacker)}, witness_path=witness)
    assert r["status"] == "REWRITTEN"


def test_truncation_before_a_witnessed_anchor_is_detected(tmp_path):
    signer = _signer()
    path, witness = tmp_path / "l.jsonl", tmp_path / "w.jsonl"
    led = Ledger(path, signer=signer)
    _fill(led)
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(witness), signer=signer)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    r = verify_all(path, public_keys=_keys(signer), witness_path=witness)
    assert r["status"] == "TRUNCATED"


def test_tail_after_the_last_anchor_is_reported_not_hidden(tmp_path):
    signer = _signer()
    path, witness = tmp_path / "l.jsonl", tmp_path / "w.jsonl"
    led = Ledger(path, signer=signer)
    _fill(led, 3)
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(witness), signer=signer)
    _fill(led, 2)
    r = verify_all(path, public_keys=_keys(signer), witness_path=witness)
    assert r["status"] == "OK"
    assert r["anchored_upto"] == 2 and r["unanchored_tail"] == 2


def test_forged_anchor_in_witness_is_rejected(tmp_path):
    signer = _signer()
    path, witness = tmp_path / "l.jsonl", tmp_path / "w.jsonl"
    led = Ledger(path, signer=signer)
    _fill(led)
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(witness), signer=signer)
    line = json.loads(witness.read_text(encoding="utf-8").splitlines()[0])
    line["sig"] = "00" * 64
    witness.write_text(json.dumps(line) + "\n", encoding="utf-8")
    assert verify_all(path, public_keys=_keys(signer), witness_path=witness)["status"] == "BAD_SIGNATURE"


def test_unsigned_v1_anchor_is_refused_when_signatures_are_required(tmp_path):
    signer = _signer()
    path, anchors = tmp_path / "l.jsonl", tmp_path / "a.jsonl"
    led = Ledger(path, signer=signer)
    _fill(led)
    anchor_ledger(led, anchors)  # no signer: anchor_version 1
    assert verify_all(path, anchors_path=anchors)["status"] == "OK"
    assert verify_all(path, public_keys=_keys(signer), anchors_path=anchors)["status"] == "UNSIGNED_ANCHOR"


# ------------------------------------------------------------------ heartbeats

class Clock:
    def __init__(self, t=1_790_000_000):
        self.t = t

    def __call__(self):
        return self.t


def _beat(led, attempted=0, recorded=0, tools=("t",), policy_hash="p1"):
    led.record_heartbeat(recorder_id="r", tools=list(tools), policy_version="v1", policy_hash=policy_hash,
                         calls_attempted=attempted, calls_recorded=recorded, interval_s=60)


def test_heartbeat_gap_is_reported(tmp_path):
    clock = Clock()
    led = Ledger(tmp_path / "l.jsonl", clock=clock)
    _beat(led)
    clock.t += 60
    _beat(led)
    clock.t += 3600  # recorder silent for an hour
    _beat(led)
    r = verify_all(led.path, max_gap_s=120)
    assert r["status"] == "HEARTBEAT_GAP"
    assert r["gaps"][0]["seconds"] == 3600
    assert verify_all(led.path, max_gap_s=7200)["status"] == "OK"


def test_no_heartbeat_at_all_fails_when_a_gap_limit_is_set(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    _fill(led, 1)
    assert verify_all(led.path, max_gap_s=60)["status"] == "NO_HEARTBEAT"


def test_calls_intercepted_but_not_recorded_are_flagged(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    _beat(led, attempted=5, recorded=4)
    assert verify_all(led.path, max_gap_s=600)["status"] == "UNRECORDED_CALLS"


def test_tool_and_policy_changes_are_listed(tmp_path):
    clock = Clock()
    led = Ledger(tmp_path / "l.jsonl", clock=clock)
    _beat(led, tools=("a",))
    clock.t += 30
    _beat(led, tools=("a", "send_email"), policy_hash="p2")
    r = verify_all(led.path, max_gap_s=60)
    assert r["status"] == "OK"
    assert r["changes"] == [{"seq": 1, "ts": r["changes"][0]["ts"], "tools_added": ["send_email"],
                             "tools_removed": [], "policy_changed": True, "policy_version": "v1"}]


# ------------------------------------------------------------------ writer safety

def _writer(path, n, signer_seed):
    led = Ledger(path, signer=Signer.from_seed(signer_seed), fsync=False)
    for i in range(n):
        led.record(agent_id="mp", session_id="s", policy_version="v", tool="t", categories=[],
                   args={"i": i}, decision="allow", result=None)


def test_concurrent_writers_from_several_processes_keep_the_chain_intact(tmp_path):
    path = tmp_path / "shared.jsonl"
    Ledger(path)
    procs = [mp.Process(target=_writer, args=(str(path), 15, SEED)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    assert all(p.exitcode == 0 for p in procs)
    r = verify_all(path, public_keys=_keys(_signer()))
    assert r["status"] == "OK" and r["records"] == 60


def test_malformed_line_is_reported_not_crashed_on(tmp_path):
    path = tmp_path / "l.jsonl"
    _fill(Ledger(path), 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1][:-5]  # cut a line in half
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert Ledger(path).verify() == (False, 1)


def test_records_have_no_floats_so_any_language_can_reproduce_the_hash(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    rec = led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[],
                     args={"x": 1.5}, decision="allow", result=None, duration_ms=12.3456)
    assert rec["duration_us"] == 12346 and isinstance(rec["duration_us"], int)
    with pytest.raises(TypeError):
        led.record_event("a2a_send", ratio=0.5)
