"""Anchoring protocol v1 (auditrail-docs/錨定協定.md): anchor, verify, witnesses."""
import hashlib
import json
import shutil
import subprocess

import pytest

from auditrail import anchor as anc
from auditrail.anchor import AnchorError, FileSink, GitSink, anchor_ledger, build_anchor, verify_anchors
from auditrail.ledger import Ledger, _canonical

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git executable not available")


def make_ledger(path, n=5, args_for=lambda i: {"i": i}):
    led = Ledger(path)
    for i in range(n):
        led.record(agent_id="a", session_id="s", policy_version="v1", tool=f"t{i}",
                   categories=[], args=args_for(i), decision="allow", result={"i": i})
    return led


def read_lines(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def write_lines(path, records):
    path.write_text("\n".join(_canonical(r) for r in records) + "\n", encoding="utf-8")


def rechain_from(path, start_seq):
    """Simulate a careful attacker: edit history and recompute every hash after it."""
    recs = read_lines(path)
    prev = recs[start_seq - 1]["hash"] if start_seq > 0 else "0" * 64
    for rec in recs[start_seq:]:
        rec["prev_hash"] = prev
        body = {k: v for k, v in rec.items() if k != "hash"}
        rec["hash"] = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
        prev = rec["hash"]
    write_lines(path, recs)


def anchor_once(ledger, anchors, sink=None):
    return anchor_ledger(ledger, anchors, sink=sink)["anchor"]


class CountingSink(FileSink):
    def __init__(self, path):
        super().__init__(path)
        self.publishes = 0
        self.pushes = 0

    def publish(self, anchor_line):
        self.publishes += 1
        return super().publish(anchor_line)

    def push(self):
        self.pushes += 1


# ------------------------------------------------------------------ normal path

def test_normal_anchor_then_verify_is_ok(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    sink = FileSink(tmp_path / "witness.jsonl")
    led = make_ledger(ledger_path, n=5)
    anchor_once(led, anchors, sink)
    r = verify_anchors(ledger_path, anchors, sinks={"file": sink})
    assert r["status"] == "OK"
    assert r["anchored_upto"] == 4
    assert r["unanchored_tail"] == 0


def test_verify_reports_tail_that_is_not_covered(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=3)
    anchor_once(led, anchors)  # local-only anchor: no sink
    for i in range(3, 6):
        led.record(agent_id="a", session_id="s", policy_version="v1", tool=f"t{i}",
                   categories=[], args={}, decision="allow", result={})
    r = verify_anchors(ledger_path, anchors)
    assert r["status"] == "OK"
    assert r["anchored_upto"] == 2
    assert r["unanchored_tail"] == 3
    assert "not covered" in r["detail"]


def test_no_anchors_yet_means_everything_is_tail(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    make_ledger(ledger_path, n=4)
    r = verify_anchors(ledger_path, tmp_path / "missing-anchors.jsonl")
    assert r["status"] == "OK"
    assert r["anchored_upto"] is None
    assert r["unanchored_tail"] == 4


def test_anchor_line_has_protocol_fields_and_sink_ref(tmp_path):
    anchors = tmp_path / "anchors.jsonl"
    make_ledger(tmp_path / "l.jsonl", n=2)
    anchor_once(Ledger(tmp_path / "l.jsonl"), anchors, FileSink(tmp_path / "w.jsonl"))
    rec = read_lines(anchors)[0]
    assert set(rec) == {"anchor_version", "seq", "head_hash", "prev_anchor", "created_at", "anchor_hash", "sink_ref"}
    assert rec["anchor_version"] == 1
    assert rec["prev_anchor"] == "0" * 64
    assert rec["sink_ref"].startswith("file:")


def test_anchor_hash_is_sha256_of_canonical_body(tmp_path):
    led = make_ledger(tmp_path / "l.jsonl", n=2)
    a = build_anchor(led)
    body = {k: a[k] for k in ("anchor_version", "seq", "head_hash", "prev_anchor", "created_at")}
    assert a["anchor_hash"] == hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def test_sink_ref_is_not_part_of_anchor_hash(tmp_path):
    anchors = tmp_path / "anchors.jsonl"
    make_ledger(tmp_path / "l.jsonl", n=2)
    rec = anchor_once(Ledger(tmp_path / "l.jsonl"), anchors, FileSink(tmp_path / "w.jsonl"))
    body = {k: rec[k] for k in ("anchor_version", "seq", "head_hash", "prev_anchor", "created_at")}
    assert rec["anchor_hash"] == hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ attacks

def test_rewriting_a_middle_record_is_detected_at_that_seq(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=6)
    anchor_once(led, anchors)
    recs = read_lines(ledger_path)
    recs[2]["tool"] = "forged"  # edit without recomputing the chain
    write_lines(ledger_path, recs)
    r = verify_anchors(ledger_path, anchors)
    assert r["status"] == "TAMPERED_LEDGER"
    assert r["bad_seq"] == 2


def test_careful_rewrite_with_recomputed_chain_is_rewritten(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=6)
    anchor_once(led, anchors)
    recs = read_lines(ledger_path)
    recs[2]["tool"] = "forged"
    write_lines(ledger_path, recs)
    rechain_from(ledger_path, 2)  # the ledger's own chain now verifies again
    assert Ledger(ledger_path).verify()[0] is True
    r = verify_anchors(ledger_path, anchors)
    assert r["status"] == "REWRITTEN"
    assert r["bad_seq"] == 5  # the anchor at seq=5 no longer matches the rewritten head


def test_truncating_before_the_anchor_is_truncated(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=5)
    anchor_once(led, anchors)
    recs = read_lines(ledger_path)
    write_lines(ledger_path, recs[:3])  # keep seq 0..2 only
    assert Ledger(ledger_path).verify()[0] is True
    r = verify_anchors(ledger_path, anchors)
    assert r["status"] == "TRUNCATED"
    assert r["max_seq"] == 2


def test_missing_ledger_with_anchors_is_truncated(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    anchor_once(make_ledger(ledger_path, n=3), anchors)
    ledger_path.unlink()
    assert verify_anchors(ledger_path, anchors)["status"] == "TRUNCATED"


def test_rewriting_any_anchor_line_is_tamper_anchor(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=6)
    anchor_once(led, anchors)
    rec = read_lines(anchors)[0]
    rec["head_hash"] = "f" * 64  # rewrite the anchored head
    anchors.write_text(_canonical(rec) + "\n", encoding="utf-8")
    r = verify_anchors(ledger_path, anchors)
    assert r["status"] == "TAMPERED_ANCHOR"
    assert r["line"] == 1


def test_breaking_the_anchor_link_is_tamper_anchor(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=2)
    anchor_once(led, anchors)
    for i in range(2, 4):
        led.record(agent_id="a", session_id="s", policy_version="v1", tool=f"t{i}",
                   categories=[], args={}, decision="allow", result={})
    anchor_once(led, anchors)
    lines = read_lines(anchors)
    lines[1]["prev_anchor"] = "0" * 64  # cut the link, keep the rest
    lines[1]["anchor_hash"] = anc._anchor_hash({k: lines[1][k] for k in anc.BODY_KEYS})
    anchors.write_text("\n".join(_canonical(x) for x in lines) + "\n", encoding="utf-8")
    r = verify_anchors(ledger_path, anchors)
    assert r["status"] == "TAMPERED_ANCHOR"
    assert r["line"] == 2


def test_malformed_anchor_line_is_tamper_anchor(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    anchor_once(make_ledger(ledger_path, n=2), anchors)
    anchors.write_text("not json\n", encoding="utf-8")
    assert verify_anchors(ledger_path, anchors)["status"] == "TAMPERED_ANCHOR"


def test_file_sink_content_changed_is_sink_mismatch(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    sink = FileSink(tmp_path / "witness.jsonl")
    anchor_once(make_ledger(ledger_path, n=3), anchors, sink)
    sink.path.write_text("", encoding="utf-8")  # the witness copy is gone or replaced
    r = verify_anchors(ledger_path, anchors, sinks={"file": sink})
    assert r["status"] == "SINK_MISMATCH"


def test_witnessed_anchor_without_its_sink_is_unreachable_not_ok(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    anchor_once(make_ledger(ledger_path, n=3), anchors, FileSink(tmp_path / "witness.jsonl"))
    r = verify_anchors(ledger_path, anchors, sinks={})
    assert r["status"] == "SINK_UNREACHABLE"


# ------------------------------------------------------------------ rules

def test_empty_ledger_is_refused(tmp_path):
    ledger_path = tmp_path / "empty.jsonl"
    with pytest.raises(AnchorError, match="empty"):
        anchor_ledger(Ledger(ledger_path), tmp_path / "anchors.jsonl")
    assert not (tmp_path / "anchors.jsonl").exists()


def test_broken_ledger_is_refused_with_first_bad_seq(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    led = make_ledger(ledger_path, n=4)
    recs = read_lines(ledger_path)
    recs[1]["tool"] = "forged"
    write_lines(ledger_path, recs)
    with pytest.raises(AnchorError) as exc:
        anchor_ledger(Ledger(ledger_path), tmp_path / "anchors.jsonl")
    assert exc.value.bad_seq == 1
    assert not (tmp_path / "anchors.jsonl").exists()


def test_repeat_anchor_on_same_head_is_idempotent(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    sink = CountingSink(tmp_path / "witness.jsonl")
    led = make_ledger(ledger_path, n=3)
    first = anchor_ledger(led, anchors, sink=sink)
    second = anchor_ledger(led, anchors, sink=sink)
    assert first["status"] == "ANCHORED"
    assert second["status"] == "UNCHANGED"
    assert len(read_lines(anchors)) == 1
    assert sink.publishes == 1


def test_new_records_after_an_anchor_produce_a_new_anchor(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=2)
    anchor_once(led, anchors)
    led.record(agent_id="a", session_id="s", policy_version="v1", tool="x",
               categories=[], args={}, decision="allow", result={})
    res = anchor_ledger(led, anchors)
    assert res["status"] == "ANCHORED"
    lines = read_lines(anchors)
    assert [x["seq"] for x in lines] == [1, 2]
    assert lines[1]["prev_anchor"] == lines[0]["anchor_hash"]


def test_anchoring_refuses_to_append_to_a_tampered_anchor_file(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=2)
    anchor_once(led, anchors)
    anchors.write_text("garbage\n", encoding="utf-8")
    led.record(agent_id="a", session_id="s", policy_version="v1", tool="x",
               categories=[], args={}, decision="allow", result={})
    with pytest.raises(AnchorError, match="fails verification"):
        anchor_ledger(led, anchors)


def test_anchor_does_not_modify_the_ledger_file(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    led = make_ledger(ledger_path, n=4)
    before = ledger_path.read_bytes()
    anchor_once(led, tmp_path / "anchors.jsonl", FileSink(tmp_path / "w.jsonl"))
    verify_anchors(ledger_path, tmp_path / "anchors.jsonl")
    assert ledger_path.read_bytes() == before


def test_anchors_and_witness_never_contain_args_or_results(tmp_path):
    secret = "SECRET-PAYLOAD-7731"
    ledger_path = tmp_path / "l.jsonl"
    led = Ledger(ledger_path)
    led.record(agent_id="a", session_id="s", policy_version="v1", tool="t",
               categories=[], args={"ssn": secret}, decision="allow", result={"echo": secret})
    anchors = tmp_path / "anchors.jsonl"
    witness = tmp_path / "w.jsonl"
    anchor_once(led, anchors, FileSink(witness))
    assert secret not in anchors.read_text(encoding="utf-8")
    assert secret not in witness.read_text(encoding="utf-8")


# ------------------------------------------------------------------ git witness

def _git(repo, *args):
    return subprocess.run([GIT, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          capture_output=True, text=True, encoding="utf-8", check=True)


@needs_git
def test_git_witness_round_trip_is_ok(tmp_path):
    repo = tmp_path / "witness"
    repo.mkdir()
    _git(repo, "init", "-q")
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    sink = GitSink(repo)
    anchor_once(make_ledger(ledger_path, n=4), anchors, sink)
    assert read_lines(anchors)[0]["sink_ref"].startswith("git:")
    r = verify_anchors(ledger_path, anchors, sinks={"git": sink})
    assert r["status"] == "OK"
    assert (repo / "anchors" / "anchors.jsonl").exists()


@needs_git
def test_git_witness_content_rewritten_by_owner_is_sink_mismatch(tmp_path):
    repo = tmp_path / "witness"
    repo.mkdir()
    _git(repo, "init", "-q")
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    sink = GitSink(repo)
    anchor_once(make_ledger(ledger_path, n=4), anchors, sink)
    # the owner rewrites the witness file and commits the change
    (repo / "anchors" / "anchors.jsonl").write_text('{"anchor_hash":"forged"}\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "rewrite")
    r = verify_anchors(ledger_path, anchors, sinks={"git": sink})
    assert r["status"] == "SINK_MISMATCH"


@needs_git
def test_git_witness_missing_repo_is_unreachable(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    anchor_once(make_ledger(ledger_path, n=2), anchors, FileSink(tmp_path / "w.jsonl"))
    lines = read_lines(anchors)
    lines[0]["sink_ref"] = "git:deadbeef"
    anchors.write_text(_canonical(lines[0]) + "\n", encoding="utf-8")
    r = verify_anchors(ledger_path, anchors, sinks={"git": GitSink(tmp_path / "no-such-repo")})
    assert r["status"] == "SINK_UNREACHABLE"


@needs_git
def test_git_publish_failure_records_no_local_anchor(tmp_path):
    ledger_path = tmp_path / "l.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    led = make_ledger(ledger_path, n=2)
    with pytest.raises(anc.SinkUnreachable):
        anchor_ledger(led, anchors, sink=GitSink(tmp_path / "not-a-repo"))
    assert not anchors.exists()


@needs_git
def test_push_is_not_called_unless_requested(tmp_path, monkeypatch):
    repo = tmp_path / "witness"
    repo.mkdir()
    _git(repo, "init", "-q")
    pushes = []
    monkeypatch.setattr(GitSink, "push", lambda self, remote="origin": pushes.append(remote))
    ledger_path = tmp_path / "l.jsonl"
    led = make_ledger(ledger_path, n=2)
    anchor_once(led, tmp_path / "a1.jsonl", GitSink(repo))
    assert pushes == []
    anchor_ledger(led, tmp_path / "a2.jsonl", sink=GitSink(repo), push=True)
    assert pushes == ["origin"]
