"""Findings from the phase 1 review of the verification core (F2: timestamps after the year 3000)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from auditrail import Ledger
from auditrail.ledger import GENESIS_HASH, _canonical, record_hash
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")


def make_ledger(path, *, calls_attempted=1, calls_recorded=1, far_future=True):
    led = Ledger(path, fsync=False)
    led.record_heartbeat(recorder_id="r", tools=["t"], policy_version="p", policy_hash="ab" * 32,
                         calls_attempted=calls_attempted, calls_recorded=calls_recorded, interval_s=60)
    led.record(agent_id="a", session_id="s", policy_version="p", policy_hash="ab" * 32, tool="t", categories=[],
               args={}, decision="allow")
    recs = list(led)
    if far_future:
        recs[-1]["ts"] = "9999-12-31T23:59:59Z"
    prev = GENESIS_HASH
    out = []
    for r in recs:
        r = {k: v for k, v in r.items() if k not in ("hash",)}
        r["prev_hash"] = prev
        r["hash"] = record_hash(prev, r)
        prev = r["hash"]
        out.append(_canonical(r))
    path.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    return path


def rust(path, *args):
    r = subprocess.run([str(BINARY), str(path), *map(str, args), "--json"], capture_output=True, text=True,
                       encoding="utf-8")
    return json.loads(r.stdout)


def test_a_far_future_timestamp_gives_heartbeat_gap_not_a_crash(tmp_path):
    p = make_ledger(tmp_path / "l.jsonl")
    res = verify_all(p, max_gap_s=3600)
    assert res["status"] == "HEARTBEAT_GAP"
    assert "9999-12-31T23:59:59Z" in json.dumps(res)


def test_a_deterministic_finding_is_not_hidden_by_the_formatting(tmp_path):
    p = make_ledger(tmp_path / "l.jsonl", calls_attempted=5, calls_recorded=3)
    res = verify_all(p, max_gap_s=3600)
    assert res["status"] == "UNRECORDED_CALLS"


@pytest.mark.skipif(BINARY is None, reason="Rust verifier not built")
@pytest.mark.parametrize("attempted,recorded,expected", [(1, 1, "HEARTBEAT_GAP"), (5, 3, "UNRECORDED_CALLS")])
def test_python_and_rust_agree_on_far_future_timestamps(tmp_path, attempted, recorded, expected):
    p = make_ledger(tmp_path / "l.jsonl", calls_attempted=attempted, calls_recorded=recorded)
    assert verify_all(p, max_gap_s=3600)["status"] == expected
    assert rust(p, "--max-gap", 3600)["status"] == expected


def test_the_gap_listing_is_formatted_as_before(tmp_path):
    from auditrail.verifier import check_heartbeats, _fmt

    assert _fmt(0) == "1970-01-01T00:00:00Z"
    assert _fmt(1_700_000_000) == "2023-11-14T22:13:20Z"
    assert _fmt(253402300799) == "9999-12-31T23:59:59Z"
    p = make_ledger(tmp_path / "l.jsonl")
    recs = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]
    problem, _ = check_heartbeats(recs, 3600)
    assert problem["status"] == "HEARTBEAT_GAP" and problem["gaps"][-1]["to"] == "9999-12-31T23:59:59Z"
