"""`auditrail report`: determinism, honesty, escaping, redaction, evaluation order, exit codes."""
import hashlib
import json
import re
from pathlib import Path

import pytest

from auditrail import Ledger, Signer, report
from auditrail.anchor import FileSink, anchor_ledger
from auditrail.cli import main
from auditrail.ledger import GENESIS_HASH, _canonical, record_hash
from auditrail.report import (
    FINDING_TABLE, LIMITS_FLOOR, NOT_VOCAB, STATUS_TABLE, build_report, explain, render_html, render_json, render_md)

ROOT = Path(__file__).resolve().parents[1]
SEED = bytes(range(32))
LIMITS_HEADING_MD = "## 10. What this report does not prove"
LIMITS_HEADING_HTML = "<h2>10. What this report does not prove</h2>"

TRICKY_TOOL = "tool-<b>&\"'-SECRET"
AGENT = "agent-SECRET-alpha"
RECORDER = "recorder-SECRET-gamma"


def write_ledger(path, signer, n=4, tool="read_x", agent=AGENT, with_refusals=True):
    led = Ledger(path, signer=signer, fsync=False)
    led.record_heartbeat(recorder_id=RECORDER, tools=sorted({tool, "send_y"}), policy_version="p1",
                         policy_hash="ab" * 32, calls_attempted=0, calls_recorded=0, interval_s=60)
    for i in range(n):
        deny = with_refusals and i % 2 == 1
        led.record(agent_id=agent, session_id="s", policy_version="p1", policy_hash="ab" * 32, tool=tool,
                   categories=["data_access"], args={"i": i}, decision="deny" if deny else "allow",
                   reason=("lethal_trifecta: would complete the trifecta" if i == 1 else
                           "unclassified_tool: no category" if deny else None))
    led.record_heartbeat(recorder_id=RECORDER, tools=sorted({tool, "send_y"}), policy_version="p1",
                         policy_hash="ab" * 32, calls_attempted=n, calls_recorded=n, interval_s=60)
    return led


@pytest.fixture
def world(tmp_path):
    signer = Signer.from_seed(SEED)
    led = write_ledger(tmp_path / "l.jsonl", signer, tool=TRICKY_TOOL)
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(tmp_path / "w.jsonl"), signer=signer)
    (tmp_path / "k.pub").write_text(signer.public_hex + "\n", encoding="utf-8")
    return tmp_path, signer


def args_for(w, **over):
    base = dict(public_key_paths=[w / "k.pub"], witness_path=w / "w.jsonl", max_gap_s=3600)
    base.update(over)
    return base


def edit_without_rehash(w, name="t.jsonl"):
    recs = [json.loads(x) for x in (w / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    recs[2]["decision"] = "allow"
    (w / name).write_text("".join(_canonical(r) + "\n" for r in recs), encoding="utf-8", newline="\n")
    return w / name


def edit_with_rehash(w, name="r.jsonl"):
    recs = [json.loads(x) for x in (w / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    recs[2]["decision"] = "allow"
    prev = GENESIS_HASH
    for r in recs:
        r["prev_hash"] = prev
        r["hash"] = record_hash(prev, r)
        prev = r["hash"]
    (w / name).write_text("".join(_canonical(r) + "\n" for r in recs), encoding="utf-8", newline="\n")
    return w / name


def outside_limits(md: str) -> str:
    return md.split(LIMITS_HEADING_MD)[0]


# ---------------------------------------------------------------- determinism

def test_same_inputs_give_identical_bytes_in_every_format(world):
    w, _ = world
    a = build_report(w / "l.jsonl", **args_for(w))
    b = build_report(w / "l.jsonl", **args_for(w))
    for fn in (render_md, render_html, render_json):
        assert fn(a) == fn(b)


def test_the_timestamp_is_the_only_difference_and_the_fingerprint_ignores_it(world):
    w, _ = world
    plain = build_report(w / "l.jsonl", **args_for(w))
    s1 = build_report(w / "l.jsonl", **args_for(w, generated_at="2026-10-15T01:02:03Z"))
    s2 = build_report(w / "l.jsonl", **args_for(w, generated_at="2030-01-01T00:00:00Z"))
    assert plain["fingerprint_sha256"] == s1["fingerprint_sha256"] == s2["fingerprint_sha256"]
    assert render_md(s1) != render_md(s2)
    for fn in (render_md, render_html, render_json):
        # the only differing lines are the stamp lines
        l1, l2 = fn(s1).splitlines(), fn(s2).splitlines()
        assert len(l1) == len(l2)
        assert [x for x, y in zip(l1, l2) if x != y] != []
        assert all(("2026-10-15T01:02:03Z" in x or "2030-01-01T00:00:00Z" in y) for x, y in zip(l1, l2) if x != y)


def test_the_fingerprint_changes_when_the_evidence_changes(world):
    w, _ = world
    a = build_report(w / "l.jsonl", **args_for(w))
    b = build_report(edit_without_rehash(w), **args_for(w))
    assert a["fingerprint_sha256"] != b["fingerprint_sha256"]


def test_cli_writes_identical_files_twice(world, capsys):
    w, _ = world
    for run in ("one", "two"):
        code = main(["report", str(w / "l.jsonl"), "--pubkey", str(w / "k.pub"), "--witness-file", str(w / "w.jsonl"),
                     "--max-gap", "3600", "--format", "all", "--out", str(w / run)])
        assert code == 0
    for ext in ("md", "html", "json"):
        assert (w / f"one.{ext}").read_bytes() == (w / f"two.{ext}").read_bytes()
    capsys.readouterr()


# ---------------------------------------------------------------- the fixed section

FLAG_SETS = [
    {}, {"public_key_paths": []}, {"witness_path": None}, {"max_gap_s": None}, {"redact": True},
    {"title": "T", "note": "N"}, {"max_rows": 1}, {"generated_at": "2026-10-15T00:00:00Z"},
    {"public_key_paths": [], "witness_path": None, "max_gap_s": None},
]


@pytest.mark.parametrize("over", FLAG_SETS, ids=lambda o: ",".join(o) or "defaults")
def test_the_limits_section_and_the_floor_are_in_every_format_under_every_option(world, over):
    w, _ = world
    data = build_report(w / "l.jsonl", **args_for(w, **over))
    md, html_, js = render_md(data), render_html(data), json.loads(render_json(data))
    assert LIMITS_HEADING_MD in md and LIMITS_HEADING_HTML in html_
    assert js["does_not_prove"]["heading"] == "What this report does not prove"
    import html as htmllib

    for sentence in LIMITS_FLOOR:
        assert sentence in md
        assert htmllib.escape(sentence, quote=True) in html_
        assert sentence in js["does_not_prove"]["floor"]


def test_the_limits_section_is_also_there_for_a_ledger_that_failed_every_check(world):
    w, _ = world
    data = build_report(edit_without_rehash(w), **args_for(w))
    assert LIMITS_HEADING_MD in render_md(data)


def test_cli_has_no_flag_that_turns_the_section_off():
    from auditrail.cli import build_parser

    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    flags = {o for act in sub.choices["report"]._actions for o in act.option_strings}
    assert not any("limit" in f or "no-" in f or "quiet" in f or "brief" in f for f in flags), flags


# ---------------------------------------------------------------- statuses

def _status_literals():
    found = set()
    for name in ("verifier.py", "anchor.py", "reconcile.py"):
        text = (ROOT / "src" / "auditrail" / name).read_text(encoding="utf-8")
        found |= set(re.findall(r"\"([A-Z][A-Z_]{3,})\"", text))
    return found - {"ANCHORED", "HEAD", "UNCHANGED"}  # an anchor command outcome, a git ref, a no-op result


def test_every_status_string_the_verifiers_can_emit_has_an_explanation():
    missing = sorted(s for s in _status_literals() if s not in STATUS_TABLE and s not in FINDING_TABLE)
    assert missing == [], f"add these to report.STATUS_TABLE / FINDING_TABLE: {missing}"


def test_the_table_has_the_two_unsupported_statuses_and_says_what_file_input_gets():
    ua = explain("UNSUPPORTED_ALGORITHM")
    assert ua["cls"] == "inconclusive"
    assert "cannot occur" in ua["means"] and "BAD_SIGNATURE" in ua["means"] and "algorithm mismatch" in ua["means"]
    assert "never means the records were left unchanged" in ua["not_means"]
    assert explain("UNSUPPORTED_FORMAT")["cls"] == "inconclusive"


def test_an_unknown_status_is_inconclusive_and_never_described_as_consistent(world, monkeypatch):
    w, _ = world
    monkeypatch.setattr(report, "verify_all", lambda *a, **k: {"status": "SOMETHING_NEW", "detail": "x"})
    data = build_report(w / "l.jsonl", **args_for(w))
    md = render_md(data)
    assert explain("SOMETHING_NEW")["cls"] == "inconclusive"
    assert "no inconsistency" not in outside_limits(md).split("### Checks that ran")[0].lower()
    assert "examination is incomplete" in md and "SOMETHING_NEW" in md
    assert "cannot explain" in md


@pytest.mark.parametrize("status", ["UNSUPPORTED_ALGORITHM", "UNSUPPORTED_FORMAT", "SINK_UNREACHABLE", "LEGACY_FORMAT"])
def test_inconclusive_statuses_are_reported_as_incomplete_not_consistent(world, monkeypatch, status):
    w, _ = world
    monkeypatch.setattr(report, "verify_all", lambda *a, **k: {"status": status, "detail": "d", "bad_seq": 0})
    md = render_md(build_report(w / "l.jsonl", **args_for(w)))
    first = md.split("### Checks that ran")[0]
    assert "examination is incomplete" in first and "not a consistent result" in first
    assert "found no inconsistency in the records they covered" not in first


# ---------------------------------------------------------------- vocabulary

def _fixtures(w):
    out = {"ok": (w / "l.jsonl", args_for(w)),
           "no-keys": (w / "l.jsonl", args_for(w, public_key_paths=[])),
           "no-witness": (w / "l.jsonl", args_for(w, witness_path=None)),
           "bare": (w / "l.jsonl", dict()),
           "tampered": (edit_without_rehash(w), args_for(w)),
           "rehashed": (edit_with_rehash(w), args_for(w)),
           "rehashed-witness-only": (edit_with_rehash(w), dict(witness_path=w / "w.jsonl")),
           "legacy": (ROOT / "tests" / "fixtures" / "legacy_v01_ledger.jsonl", dict())}
    return out


def test_no_forbidden_vocabulary_outside_the_quoted_limits(world, monkeypatch):
    w, _ = world
    texts = {}
    for name, (path, kw) in _fixtures(w).items():
        data = build_report(path, **kw)
        texts[name] = (render_md(data), render_html(data), render_json(data))
    for status in ("UNSUPPORTED_ALGORITHM", "UNSUPPORTED_FORMAT", "SINK_UNREACHABLE", "HEARTBEAT_GAP", "MISMATCH"):
        monkeypatch.setattr(report, "verify_all", lambda *a, _s=status, **k: {"status": _s, "detail": "d"})
        data = build_report(w / "l.jsonl", **args_for(w))
        texts[status] = (render_md(data), render_html(data), render_json(data))
    for name, (md, html_, js) in texts.items():
        bodies = [outside_limits(md), html_.split(LIMITS_HEADING_HTML)[0]]
        payload = json.loads(js)
        payload.pop("does_not_prove")
        bodies.append(json.dumps(payload))
        for body in bodies:
            hit = NOT_VOCAB.search(body)
            assert hit is None, f"{name}: forbidden word {hit.group(0)!r} near {body[max(0, hit.start()-60):hit.end()+60]!r}"


def test_the_ok_result_is_worded_as_no_inconsistency_found(world):
    w, _ = world
    md = render_md(build_report(w / "l.jsonl", **args_for(w)))
    assert "found no inconsistency in the records they covered" in md
    assert "does not mean the recorded actions were appropriate" in md


def test_wrapped_tools_only_is_stated_in_the_result_and_in_the_heartbeat_section(world):
    w, _ = world
    md = render_md(build_report(w / "l.jsonl", **args_for(w)))
    result = md.split("## 2.")[0]
    heartbeats = md.split("## 6. Heartbeats")[1].split("## 7.")[0]
    for part in (result, heartbeats):
        assert "went through the recorder's wrapped tools" in part or "tool that was not wrapped leaves no record" in part
    assert "was not wrapped leaves no record" in result and "was not wrapped leaves no record" in heartbeats


def test_a_tail_after_the_last_anchor_is_named_with_the_no_keys_wording(world):
    w, signer = world
    led = Ledger(w / "l.jsonl", signer=signer, fsync=False)
    led.record(agent_id=AGENT, session_id="s", policy_version="p1", policy_hash="ab" * 32, tool="t",
               categories=["internal"], args={}, decision="allow", reason=None)
    data = build_report(w / "l.jsonl", witness_path=w / "w.jsonl")  # witness only, no keys
    md = render_md(data)
    assert data["overall"]["status"] == "OK"
    assert data["coverage"]["unanchored_tail"] == 1
    assert "come after the last anchor held by a witness" in md and "OK with a note" in md
    assert "Signatures were NOT CHECKED" in md


# ---------------------------------------------------------------- evaluation order and honesty after a failure

def test_after_a_failed_chain_the_later_sections_are_not_evaluated_and_nothing_is_presented_as_fact(world):
    w, _ = world
    data = build_report(edit_without_rehash(w), **args_for(w))
    md = render_md(data)
    assert data["overall"]["status"] == "TAMPERED_LEDGER" and data["chain"]["state"] == "failed"
    assert data["scope"] is None and data["policy"]["evaluated"] is False and data["refusals"]["evaluated"] is False
    assert "Not evaluated: the records failed an earlier check." in md
    assert "Records before seq 2 are consistent with each other." in md
    assert "| Decision | Count |" not in md  # no decisions table computed from untrusted records


def test_a_definite_finding_from_the_witness_is_reported_not_hidden(world):
    w, _ = world
    data = build_report(edit_with_rehash(w), witness_path=w / "w.jsonl")  # no keys: the chain alone holds
    assert data["overall"]["status"] == "REWRITTEN"
    assert "REWRITTEN" in render_md(data)


def test_a_signature_failure_is_the_overall_status_with_keys(world):
    w, _ = world
    data = build_report(edit_with_rehash(w), **args_for(w))
    assert data["overall"]["status"] == "BAD_SIGNATURE" and data["overall"]["bad_seq"] == 2


# ---------------------------------------------------------------- escaping, self-containment, redaction

def test_title_note_and_names_are_escaped_in_html_and_markdown(world):
    w, _ = world
    nasty = "<script>alert(1)</script> & \"q\" 'a'"
    data = build_report(w / "l.jsonl", **args_for(w, title=nasty, note=nasty))
    html_, md = render_html(data), render_md(data)
    assert "<script" not in html_ and "&lt;script&gt;" in html_
    assert "&amp;" in html_ and "&quot;q&quot;" in html_ and "&#x27;a&#x27;" in html_
    assert "<script" not in md and "&lt;script&gt;" in md
    assert "<b>" not in html_ and "&lt;b&gt;" in html_, "the tool name must be escaped too"
    assert "supplied by whoever generated this report; not examined" in md
    assert json.loads(render_json(data))["title"] == nasty


def test_the_html_is_self_contained(world):
    w, _ = world
    html_ = render_html(build_report(w / "l.jsonl", **args_for(w)))
    for needle in ("<script", "http://", "https://", "<link", "@import", "url(", " src=", "<img", "<iframe"):
        assert needle not in html_, needle
    assert html_.startswith("<!doctype html>")


def test_redact_removes_every_original_name_and_keeps_the_counts(world):
    w, _ = world
    plain = build_report(w / "l.jsonl", **args_for(w))
    red = build_report(w / "l.jsonl", **args_for(w, redact=True))
    for text in (render_md(red), render_html(red), render_json(red)):
        for secret in (AGENT, TRICKY_TOOL, RECORDER, "SECRET", "l.jsonl", "w.jsonl", "k.pub"):
            assert secret not in text, secret
        assert "agent-" in text and "tool-" in text and "recorder-" in text
    assert red["refusals"]["decisions"] == plain["refusals"]["decisions"]
    assert red["scope"]["records"] == plain["scope"]["records"]
    again = build_report(w / "l.jsonl", **args_for(w, redact=True))
    assert render_md(again) == render_md(red)
    assert red["fingerprint_sha256"] != plain["fingerprint_sha256"]


# ---------------------------------------------------------------- content

def test_refusal_classes_include_unclassified_and_the_trifecta(world):
    w, _ = world
    rf = build_report(w / "l.jsonl", **args_for(w))["refusals"]
    assert rf["by_class"] == {"lethal_trifecta": 1, "unclassified_tool": 1}
    assert rf["decisions"] == {"allow": 2, "deny": 2}


def test_policy_timeline_and_tool_changes(tmp_path):
    s = Signer.from_seed(SEED)
    led = Ledger(tmp_path / "l.jsonl", signer=s, fsync=False)
    led.record_heartbeat(recorder_id="r", tools=["a"], policy_version="p1", policy_hash="11" * 32,
                         calls_attempted=0, calls_recorded=0, interval_s=60)
    led.record(agent_id="x", session_id="s", policy_version="p1", policy_hash="11" * 32, tool="a", categories=["internal"],
               args={}, decision="allow", reason=None)
    led.record_heartbeat(recorder_id="r", tools=["a", "b"], policy_version="p2", policy_hash="22" * 32,
                         calls_attempted=1, calls_recorded=1, interval_s=60)
    led.record(agent_id="x", session_id="s", policy_version="p2", policy_hash="22" * 32, tool="b", categories=["internal"],
               args={}, decision="allow", reason=None)
    data = build_report(tmp_path / "l.jsonl")
    assert [r["policy_version"] for r in data["policy"]["runs"]] == ["p1", "p2"]
    assert data["heartbeats"]["tool_changes"] == [{"seq": 2, "ts": data["heartbeats"]["tool_changes"][0]["ts"],
                                                    "added": ["b"], "removed": []}]


def test_heartbeat_gap_is_listed_with_its_period(tmp_path):
    clock = {"t": 1_790_000_000}
    s = Signer.from_seed(SEED)
    led = Ledger(tmp_path / "l.jsonl", signer=s, fsync=False, clock=lambda: clock["t"])
    for gap in (0, 60, 3600):
        clock["t"] += gap
        led.record_heartbeat(recorder_id="r", tools=["a"], policy_version="p", policy_hash=None, calls_attempted=0,
                             calls_recorded=0, interval_s=60)
    data = build_report(tmp_path / "l.jsonl", max_gap_s=120)
    assert data["overall"]["status"] == "HEARTBEAT_GAP"
    assert data["heartbeats"]["gaps"] and data["heartbeats"]["gaps"][0]["seconds"] == 3600
    assert "HEARTBEAT_GAP" in render_md(data)


def test_a2a_section_matches_both_sides_and_names_one_sided_messages(tmp_path):
    a, b = Signer.from_seed(SEED), Signer.from_seed(bytes(range(32, 64)))
    la = Ledger(tmp_path / "a.jsonl", signer=a, fsync=False)
    lb = Ledger(tmp_path / "b.jsonl", signer=b, fsync=False)
    la.record_event("a2a_send", agent_id="alice", peer="bob", msg_id="m1", msg_digest="d1")
    lb.record_event("a2a_recv", agent_id="bob", peer="alice", msg_id="m1", msg_digest="d1", status="accepted")
    lb.record_event("a2a_recv", agent_id="bob", peer="alice", msg_id="m2", msg_digest="d2", status="accepted")
    data = build_report(tmp_path / "a.jsonl", peer_ledgers=[tmp_path / "b.jsonl"], agents=["alice", "bob"])
    assert data["a2a"]["status"] == "MISMATCH" and data["a2a"]["matched"] == 1
    assert [f["type"] for f in data["a2a"]["findings"]] == ["RECV_WITHOUT_SEND"]
    assert "RECV_WITHOUT_SEND" in render_md(data)
    none = build_report(tmp_path / "a.jsonl")
    assert "Not examined: no peer ledgers were given" in render_md(none)


def test_max_rows_limits_lists_but_not_counts(tmp_path):
    s = Signer.from_seed(SEED)
    led = Ledger(tmp_path / "l.jsonl", signer=s, fsync=False)
    for i in range(12):
        led.record(agent_id="x", session_id="s", policy_version="p", policy_hash=None, tool=f"tool{i:02d}",
                   categories=["internal"], args={}, decision="deny", reason="other")
    data = build_report(tmp_path / "l.jsonl", max_rows=3)
    md = render_md(data)
    assert data["refusals"]["decisions"] == {"deny": 12}
    assert sum(data["refusals"]["by_tool"].values()) == 12, "counts stay complete"
    assert "9 more tool(s) not shown; counts above are complete." in md


# ---------------------------------------------------------------- CLI

def test_cli_exit_codes_and_streams(world, capsys):
    w, _ = world
    common = ["--pubkey", str(w / "k.pub"), "--witness-file", str(w / "w.jsonl"), "--max-gap", "3600"]
    assert main(["report", str(w / "l.jsonl"), *common]) == 0
    assert "found no inconsistency" in capsys.readouterr().out
    assert main(["report", str(edit_without_rehash(w)), *common]) == 1
    assert "TAMPERED_LEDGER" in capsys.readouterr().out
    assert main(["report", str(w / "missing.jsonl")]) == 2
    assert "no report was produced" in capsys.readouterr().err
    assert main(["report", str(w / "l.jsonl"), "--generated-at", "yesterday"]) == 2
    assert main(["report", str(w / "l.jsonl"), "--format", "all"]) == 2
    (w / "bad.pub").write_text("not a key", encoding="utf-8")
    assert main(["report", str(w / "l.jsonl"), "--pubkey", str(w / "bad.pub")]) == 2
    assert main(["report", str(w / "l.jsonl"), "--generated-at", "now", "--format", "json"]) == 0
    stamped = json.loads(capsys.readouterr().out)
    assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", stamped["generated_at"])


def test_legacy_ledger_report_is_inconclusive_and_says_how_to_check_it(capsys):
    code = main(["report", str(ROOT / "tests" / "fixtures" / "legacy_v01_ledger.jsonl")])
    out = capsys.readouterr().out
    assert code == 1 and "LEGACY_FORMAT" in out and "legacy-v01" in out
    assert "found no inconsistency in the records they covered" not in out.split("### Checks that ran")[0]


# ---------------------------------------------------------------- T-036 R-1: redaction touches name fields only

COLLIDING_TOOLS = ["LEDGER", "TAMPERED", "BAD", "SIGNATURE", "OK", "records", "kinds", "detail", "e", "status", "scope"]


@pytest.mark.parametrize("tool", COLLIDING_TOOLS)
def test_redact_never_rewrites_the_status_or_the_structure(tmp_path, tool):
    signer = Signer.from_seed(SEED)
    write_ledger(tmp_path / "l.jsonl", signer, tool=tool, agent="a2" if tool == "e" else "status")
    (tmp_path / "k.pub").write_text(signer.public_hex + "\n", encoding="utf-8")
    bad = edit_without_rehash(tmp_path)
    for target in (tmp_path / "l.jsonl", bad):
        plain = build_report(target, public_key_paths=[tmp_path / "k.pub"], max_gap_s=3600)
        red = build_report(target, public_key_paths=[tmp_path / "k.pub"], max_gap_s=3600, redact=True)
        assert red["overall"]["status"] == plain["overall"]["status"]
        assert json.loads(render_json(red))["overall"]["status"] == plain["overall"]["status"]
        assert render_md(red).count(f"Verifier status: {plain['overall']['status']}.") == 1
        for key in ("scope", "refusals", "heartbeats", "a2a", "chain"):
            assert (red[key] is None) == (plain[key] is None)
        if plain["scope"]:
            assert red["scope"]["kinds"] == plain["scope"]["kinds"]
        if plain["refusals"]["evaluated"]:
            assert tool not in red["refusals"]["by_tool"] and tool not in red["heartbeats"]["tool_lists"]
            assert sum(red["refusals"]["by_tool"].values()) == sum(plain["refusals"]["by_tool"].values())


def test_redact_replaces_whole_words_in_the_verifiers_free_text(tmp_path):
    signer = Signer.from_seed(SEED)
    write_ledger(tmp_path / "l.jsonl", signer, tool="read_x", agent="agent-q")
    bad = edit_without_rehash(tmp_path)
    red = build_report(bad, public_key_paths=[], redact=True)
    assert red["overall"]["status"] == "TAMPERED_LEDGER"
    assert "t.jsonl" not in json.dumps(red)


def test_redact_codes_are_labelled_not_secret_and_salt_changes_them(world):
    w, _ = world
    plain = build_report(w / "l.jsonl", **args_for(w, redact=True))
    salted = build_report(w / "l.jsonl", **args_for(w, redact=True, redact_salt="hunter2-secret"))
    assert plain["refusals"]["by_agent"] and salted["refusals"]["by_agent"]
    assert set(plain["refusals"]["by_agent"]) != set(salted["refusals"]["by_agent"])
    for text in (render_md(salted), render_html(salted), render_json(salted)):
        assert "hunter2-secret" not in text
    md_plain, md_salted = render_md(plain), render_md(salted)
    assert "no salt was supplied" in md_plain and "not secrets" in md_plain
    assert "mixed with a salt" in md_salted and "no salt was supplied" not in md_salted
    for must in ("policy version strings", "timestamps", "counts", "input file SHA-256"):
        assert must in md_plain
    unredacted = render_md(build_report(w / "l.jsonl", **args_for(w)))
    assert "not secrets" not in unredacted


def test_redact_does_not_mask_title_and_note_and_says_so(world):
    w, _ = world
    red = build_report(w / "l.jsonl", **args_for(w, redact=True, title="about " + AGENT, note="n " + RECORDER))
    md = render_md(red)
    assert AGENT in md and "It was NOT masked by --redact" in md
    assert md.count("It was NOT masked by --redact") == 2
