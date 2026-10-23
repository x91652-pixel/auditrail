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


# ---------------------------------------------------------------- F3: hostile content in a git witness
import os  # noqa: E402

from auditrail import Signer  # noqa: E402
from auditrail.anchor import FileSink, GitSink, anchor_ledger  # noqa: E402


def _git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t.invalid"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def git_world(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    repo = tmp_path / "witness"
    repo.mkdir()
    _git(repo, "init", "-q")
    signer = Signer.from_seed(bytes(range(32)))
    led = Ledger(tmp_path / "l.jsonl", signer=signer, fsync=False)
    for i in range(2):
        led.record(agent_id="a", session_id="s", policy_version="p", policy_hash="ab" * 32, tool="t",
                   categories=[], args={"i": i}, decision="allow")
    anchor_ledger(led, tmp_path / "a.jsonl", sink=GitSink(repo), signer=signer)
    return tmp_path, repo, {signer.key_id: signer.public_hex}


def _verify(w, repo, keys):
    return verify_all(w / "l.jsonl", public_keys=keys, anchors_path=w / "a.jsonl", sinks={"git": GitSink(repo)})


def _replace_witness(repo, content: bytes):
    f = repo / "anchors" / "anchors.jsonl"
    f.write_bytes(content)
    _git(repo, "add", "--", "anchors/anchors.jsonl")
    _git(repo, "commit", "-q", "-m", "x")


def test_a_clean_git_witness_is_still_ok(git_world):
    w, repo, keys = git_world
    assert _verify(w, repo, keys)["status"] == "OK"


@pytest.mark.parametrize("junk", [b"[1]\n", b"7\n", b'"text"\n', b"null\n", b"\xff\xfe garbage\n", b"{not json\n"])
def test_hostile_lines_in_the_git_witness_are_not_a_crash(git_world, junk):
    w, repo, keys = git_world
    good = (repo / "anchors" / "anchors.jsonl").read_bytes()
    _replace_witness(repo, junk + good)  # unusable line first, the real anchor still there: the anchor is found
    assert _verify(w, repo, keys)["status"] == "OK"
    _replace_witness(repo, junk)  # only the unusable line: the anchor is not in the witness
    res = _verify(w, repo, keys)
    assert res["status"] == "SINK_MISMATCH", res


def test_a_non_utf8_file_witness_is_not_a_crash(tmp_path):
    sink = FileSink(tmp_path / "w.jsonl")
    (tmp_path / "w.jsonl").write_bytes(b"\xff\xfe\n[1]\n")
    assert sink.fetch_contains("file:w.jsonl", "00" * 32) is False


# ---------------------------------------------------------------- F4: anchored_upto is the highest anchored seq
def _unordered_anchors(tmp_path, order):
    import hashlib

    led = Ledger(tmp_path / "l.jsonl", fsync=False)
    for i in range(5):
        led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=[], args={"i": i},
                   decision="allow")
    recs = list(led)
    prev, lines = "0" * 64, []
    for seq in order:
        body = {"anchor_version": 1, "seq": seq, "head_hash": recs[seq]["hash"], "prev_anchor": prev,
                "created_at": "2026-01-01T00:00:00Z"}
        h = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        lines.append(_canonical({**body, "anchor_hash": h}))
        prev = h
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return tmp_path / "l.jsonl", tmp_path / "a.jsonl"


@pytest.mark.parametrize("order,upto", [((3, 1), 3), ((1, 3), 3), ((0, 4, 2), 4)])
def test_the_owner_anchors_file_reports_the_highest_seq_not_the_last_line(tmp_path, order, upto):
    ledger, anchors = _unordered_anchors(tmp_path, order)
    res = verify_all(ledger, anchors_path=anchors)
    assert res["status"] == "OK" and res["anchored_upto"] == upto and res["unanchored_tail"] == 4 - upto


@pytest.mark.skipif(BINARY is None, reason="Rust verifier not built")
@pytest.mark.parametrize("order", [(3, 1), (1, 3), (0, 4, 2)])
@pytest.mark.parametrize("flag,pyflag", [("--anchors", "anchors_path"), ("--witness", "witness_path")])
def test_python_and_rust_report_the_same_coverage_for_unordered_anchors(tmp_path, order, flag, pyflag):
    ledger, anchors = _unordered_anchors(tmp_path, order)
    py = verify_all(ledger, **{pyflag: anchors})
    rs = rust(ledger, flag, anchors)
    assert (py["status"], py["anchored_upto"], py["unanchored_tail"]) == (rs["status"], rs["anchored_upto"], rs["unanchored_tail"])
