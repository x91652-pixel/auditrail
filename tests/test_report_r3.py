"""T-036 R-3: 'Checks that ran' and 'Not checked' follow the actual outcomes, never the flags."""
import json
from pathlib import Path

import pytest

from auditrail import Ledger, Signer
from auditrail import report
from auditrail.report import build_report, render_html, render_json, render_md

SEED = bytes(range(32))


def make_ledger(path, signer, n=3, kinds=("allow",)):
    led = Ledger(path, signer=signer, fsync=False)
    for i in range(n):
        led.record(agent_id="a", session_id="s", policy_version="p", policy_hash="ab" * 32, tool="x",
                   categories=["c"], args={"i": i}, decision="allow")
    return led


@pytest.fixture
def env(tmp_path):
    signer = Signer.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", signer)
    (tmp_path / "k.pub").write_text(signer.public_hex + "\n", encoding="utf-8")
    return tmp_path, signer


def section(md, heading, nxt):
    return md.split(heading)[1].split(nxt)[0]


def lists(md):
    """(checks that ran, not checked) as raw markdown text blocks from the Result section."""
    res = md.split("## 1. Result")[1].split("## 2.")[0]
    ran = res.split("### Checks that ran")[1].split("### Not checked")[0]
    nc = res.split("### Not checked")[1]
    return res, ran, nc


# --- L-1: an anchors file or witness copy with no anchors in it
@pytest.mark.parametrize("content", ["", "\n", "  \n\n \n"])
@pytest.mark.parametrize("which", ["witness_path", "anchors_path"])
def test_l1_an_empty_witness_or_anchor_file_is_not_a_comparison(env, content, which):
    w, _ = env
    (w / "e.jsonl").write_text(content, encoding="utf-8")
    data = build_report(w / "l.jsonl", public_key_paths=[w / "k.pub"], **{which: w / "e.jsonl"})
    md = render_md(data)
    res, ran, nc = lists(md)
    assert data["overall"]["status"] == "OK"
    label = "witness copy" if which == "witness_path" else "owner's anchors file"
    assert f"The {label}" not in ran.replace("holds no anchors", ""), ran
    assert f"The {label} that was given holds no anchors: nothing was compared against it." in nc
    assert "removal of records and whole-chain" in nc
    assert "holds no anchors" in md.split("## 4.")[1].split("## 5.")[0] or "empty: nothing compared" in md
    for out in (md, render_html(data)):
        assert "0 witnessed anchor(s) match" not in out.split("## 5.")[0]


# --- L-2: agent-to-agent messages that could not be compared
def test_l2_a_ledger_reconciled_against_itself_is_named(env):
    w, signer = env
    led = Ledger(w / "a.jsonl", signer=signer, fsync=False)
    led.record_event("a2a_send", agent_id="a", peer="b", msg_id="m1", msg_digest="1" * 64)
    (w / "copy.jsonl").write_bytes((w / "a.jsonl").read_bytes())
    data = build_report(w / "a.jsonl", public_key_paths=[w / "k.pub"], peer_ledgers=[w / "copy.jsonl", w / "a.jsonl"])
    md = render_md(data)
    res, ran, nc = lists(md)
    assert "same content as the ledger itself" in nc
    assert "Agent-to-agent messages" not in ran
    assert "No agent-to-agent message was compared against another party" in nc
    assert "not an independent record" in md.split("## 9.")[1]


def test_l2_messages_without_the_other_side_are_counted_as_not_compared(env):
    w, signer = env
    led = Ledger(w / "a.jsonl", signer=signer, fsync=False)
    for i in range(2):
        led.record_event("a2a_send", agent_id="a", peer="b", msg_id=f"m{i}", msg_digest=str(i) * 64)
    other = Ledger(w / "c.jsonl", signer=signer, fsync=False)
    other.record(agent_id="c", session_id="s", policy_version="p", policy_hash="ab" * 32, tool="x",
                 categories=["c"], args={}, decision="allow")
    data = build_report(w / "a.jsonl", public_key_paths=[w / "k.pub"], peer_ledgers=[w / "c.jsonl"])
    res, ran, nc = lists(render_md(data))
    assert data["a2a"]["unverifiable"] == 2
    assert "2 message\(s\) could not be compared" in nc
    assert "Agent-to-agent messages" not in ran


# --- L-3: no key
def test_l3_without_a_key_no_signature_wording_anywhere(env):
    w, _ = env
    data = build_report(w / "l.jsonl")
    md = render_md(data)
    res, ran, nc = lists(md)
    assert "Signatures against the trusted keys" not in ran
    assert "Signatures were NOT CHECKED" in nc
    table = md.split("## 4.")[1].split("## 5.")[0]
    assert "signatures not checked: no key given" in table
    assert "Hash chain, signatures and field rules" not in table
    assert "Hash chain, signatures and field rules" in render_md(build_report(w / "l.jsonl",
                                                                              public_key_paths=[w / "k.pub"]))


# --- L-4: an empty ledger
@pytest.mark.parametrize("with_key", [True, False])
def test_l4_an_empty_ledger_is_not_reported_as_having_no_inconsistency(env, with_key):
    w, _ = env
    (w / "e.jsonl").write_text("", encoding="utf-8")
    data = build_report(w / "e.jsonl", public_key_paths=[w / "k.pub"] if with_key else (), max_gap_s=60)
    md = render_md(data)
    res, ran, nc = lists(md)
    assert "The ledger holds no records. Nothing was examined" in res
    assert "found no inconsistency" not in md.split("## 10.")[0]
    assert "The ledger holds no records: nothing was examined" in nc
    assert "Hash chain and field rules over the records." not in ran
    assert "No check ran over any record." in ran
    assert "Heartbeats against a limit" not in ran


def test_not_checked_with_nothing_to_list_carries_no_reassurance(env, tmp_path):
    w, signer = env
    from auditrail.anchor import FileSink, anchor_ledger

    led = Ledger(w / "l2.jsonl", signer=signer, fsync=False)
    led.record_heartbeat(recorder_id="r", tools=["x"], policy_version="p", policy_hash="ab" * 32, calls_attempted=0,
                         calls_recorded=0, interval_s=60)
    anchor_ledger(led, w / "a2.jsonl", sink=FileSink(w / "w2.jsonl"), signer=signer)
    data = build_report(w / "l2.jsonl", public_key_paths=[w / "k.pub"], witness_path=w / "w2.jsonl",
                        max_gap_s=3600)
    assert data["not_checked"] == []
    md = render_md(data)
    nc = md.split("### Not checked")[1].split("## 2.")[0]
    assert "Every check that was requested ran" not in md
    assert "Nothing further was requested. The limits of the checks themselves are in section 10." in nc
    assert "No additional item was left unchecked" not in md


def test_the_result_carries_the_added_fixed_sentences(env):
    w, _ = env
    md = render_md(build_report(w / "l.jsonl"))
    res = md.split("## 1. Result")[1].split("## 2.")[0]
    assert "This report is not signed and can be edited after it was made." in res
    assert "does not vouch for the content and is not a seal" in res
    assert "none of the above holds" in res
    assert "Verifier's original wording:" in res
    assert "this tool does not confirm where they came from" in render_md(
        build_report(w / "l.jsonl", public_key_paths=[w / "k.pub"]))
    assert json.loads(render_json(build_report(w / "l.jsonl")))["checks_ran"]


# --- T-038 C-3: a copy that differs in bytes is still the same ledger; peers' keys are shown
def test_c3_a_peer_that_is_the_same_records_in_other_bytes_is_named(env):
    w, signer = env
    led = Ledger(w / "a.jsonl", signer=signer, fsync=False)
    led.record_event("a2a_send", agent_id="a", peer="b", msg_id="m1", msg_digest="1" * 64)
    raw = (w / "a.jsonl").read_bytes()
    variants = {"blank-line": raw + b"\n", "crlf": raw.replace(b"\n", b"\r\n"), "leading-blank": b"\n" + raw}
    named = 0
    for name, b in variants.items():
        (w / f"{name}.jsonl").write_bytes(b)
        data = build_report(w / "a.jsonl", public_key_paths=[w / "k.pub"], peer_ledgers=[w / f"{name}.jsonl"])
        md = render_md(data)
        if "same content as the ledger itself" in md:
            named += 1
        else:
            # a variant the strict reader refuses is reported through the reconcile status, never as independent
            assert data["a2a"]["status"] != "OK" or data["a2a"]["peers"][0]["records"] is not None, name
    assert named == 3


def test_c3_peer_keys_and_record_counts_are_printed_and_same_key_is_flagged(env):
    w, signer = env
    la = Ledger(w / "a.jsonl", signer=signer, fsync=False)
    la.record_event("a2a_send", agent_id="a", peer="b", msg_id="m1", msg_digest="1" * 64)
    lb = Ledger(w / "b.jsonl", signer=signer, fsync=False)
    lb.record_event("a2a_recv", agent_id="b", peer="a", msg_id="m1", msg_digest="1" * 64, status="accepted")
    data = build_report(w / "a.jsonl", public_key_paths=[w / "k.pub"], peer_ledgers=[w / "b.jsonl"])
    md = render_md(data)
    res, ran, nc = lists(md)
    kid = signer.key_id
    assert kid in md.split("## 9.")[1]
    assert "1 record\(s\)" in md.split("## 9.")[1]
    assert report.INDEPENDENCE in md.split("## 9.")[1].replace("\\", "")
    assert "The same signing key is a clue that it is not; a different key does not show that it is." in ran
    assert "same signing key as the ledger" in ran and kid in ran
    nokey = render_md(build_report(w / "a.jsonl", peer_ledgers=[w / "b.jsonl"]))
    assert "Peer ledger signatures were not checked" in nokey
    assert "were not checked \(no public key was given\)" in nokey.split("## 9.")[1]


# --- T-038 C-4: no reassurance where nothing was examined
LEGACY = Path(__file__).resolve().parent / "fixtures" / "legacy_v01_ledger.jsonl"


def test_c4_legacy_ledger_says_it_was_not_examined(env):
    md = render_md(build_report(LEGACY))
    res, ran, nc = lists(md)
    assert "The ledger was not examined \(v0.1 format; see LEGACY_FORMAT\)." in nc
    for reassurance in ("Nothing further was requested", "No additional item was left unchecked"):
        assert reassurance not in md


def test_c4_empty_ledger_has_no_reassurance_in_not_checked(env):
    w, _ = env
    (w / "e.jsonl").write_text("", encoding="utf-8")
    md = render_md(build_report(w / "e.jsonl", public_key_paths=[w / "k.pub"], max_gap_s=60))
    assert "Nothing further was requested" not in md and "No additional item was left unchecked" not in md


def test_c4_no_anchor_given_is_said_directly(env):
    w, _ = env
    md = render_md(build_report(w / "l.jsonl", public_key_paths=[w / "k.pub"]))
    assert "no anchor was given \(or the file held none\)" in md.split("## 2.")[0]
    assert "or no anchor was given" not in md


# --- T-040 P-1: an unclean check on another party's ledger changes the exit code and is on the first screen
from auditrail.cli import main  # noqa: E402

SENTENCE = ("A check on another party's ledger did not come out clean: see section 9. The exit code is at "
            "least 1 for that reason.")


def _pair(w, signer, peer_signer=None):
    la = Ledger(w / "a.jsonl", signer=signer, fsync=False)
    la.record_event("a2a_send", agent_id="a", peer="b", msg_id="m1", msg_digest="1" * 64)
    lb = Ledger(w / "b.jsonl", signer=peer_signer or signer, fsync=False)
    lb.record_event("a2a_recv", agent_id="b", peer="a", msg_id="m1", msg_digest="1" * 64, status="accepted")
    return w / "a.jsonl", w / "b.jsonl"


def _run_json(capsys, *argv):
    code = main(["report", "--format", "json", *map(str, argv)])
    return code, json.loads(capsys.readouterr().out)


def _break_peer(kind, w, signer):
    a, b = _pair(w, signer)
    if kind == "tampered":
        recs = [json.loads(x) for x in b.read_text(encoding="utf-8").splitlines()]
        recs[0]["status"] = "rejected"
        b.write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in recs), encoding="utf-8")
    elif kind == "unknown_key":
        a, b = _pair(w, signer, Signer.from_seed(bytes(range(1, 33))))
    elif kind == "unsigned":
        Ledger(w / "b.jsonl", fsync=False)  # no signer
        b.unlink()
        lb = Ledger(b, fsync=False)
        lb.record_event("a2a_recv", agent_id="b", peer="a", msg_id="m1", msg_digest="1" * 64, status="accepted")
    elif kind == "bom":
        b.write_bytes(b"\xef\xbb\xbf" + b.read_bytes())
    elif kind == "one_sided":
        lb = Ledger(w / "b.jsonl", signer=signer, fsync=False)  # a second, unmatched receive
        lb.record_event("a2a_recv", agent_id="b", peer="a", msg_id="m2", msg_digest="2" * 64, status="accepted")
    return a, b


@pytest.mark.parametrize("kind", ["tampered", "unknown_key", "unsigned", "bom", "one_sided"])
def test_p1_an_unclean_peer_check_is_on_the_first_screen_and_exit_1(env, capsys, kind):
    w, signer = env
    a, b = _break_peer(kind, w, signer)
    clean_main = build_report(a, public_key_paths=[w / "k.pub"])
    assert clean_main["overall"]["status"] == "OK"
    code, js = _run_json(capsys, a, "--pubkey", w / "k.pub", "--peer-ledger", b)
    assert code == 1
    assert js["overall"]["status"] == "OK", "the main ledger's status is never rewritten"
    assert js["overall"]["secondary"] and js["overall"]["secondary"][0]["status"] != "OK"
    md = render_md(build_report(a, public_key_paths=[w / "k.pub"], peer_ledgers=[b]))
    assert SENTENCE in md.split("## 2.")[0]


def test_p1_a_clean_peer_gives_exit_0_and_no_sentence(env, capsys):
    w, signer = env
    a, b = _pair(w, signer)
    code, js = _run_json(capsys, a, "--pubkey", w / "k.pub", "--peer-ledger", b)
    assert code == 0 and js["overall"]["secondary"] == []
    md = render_md(build_report(a, public_key_paths=[w / "k.pub"], peer_ledgers=[b]))
    assert "did not come out clean" not in md


def test_p1_a_different_peer_key_still_gets_the_independence_sentence(env):
    w, signer = env
    a, b = _pair(w, signer, Signer.from_seed(bytes(range(1, 33))))
    (w / "k2.pub").write_text(Signer.from_seed(bytes(range(1, 33))).public_hex + "\n", encoding="utf-8")
    md = render_md(build_report(a, public_key_paths=[w / "k.pub", w / "k2.pub"], peer_ledgers=[b]))
    sec9 = md.split("## 9.")[1]
    assert "a different key does not show that it is" in sec9
    assert "Same signing key as the ledger" not in sec9


def test_b_the_redaction_note_gives_the_reason_key_ids_stay_visible(env):
    w, _ = env
    md = render_md(build_report(w / "l.jsonl", redact=True))
    assert "Key ids are left visible because they are the identifier you compare with the --pubkey file" in md


def test_t042_with_a_secondary_finding_the_unclean_sentence_comes_first_and_ok_is_limited_to_the_main_ledger(env):
    w, signer = env
    a, b = _break_peer("tampered", w, signer)
    md = render_md(build_report(a, public_key_paths=[w / "k.pub"], peer_ledgers=[b]))
    res = md.split("## 1. Result")[1].split("## 2.")[0]
    first_para = [x for x in res.split("\n\n") if x.strip() and not x.startswith("###")][0]
    assert first_para.startswith(SENTENCE)
    assert res.index("found no inconsistency") > res.index("did not come out clean")
    assert "Verifier status \(main ledger\): OK." in res
    assert "The checks that were run found no inconsistency in the evidence they covered" not in md.split("## 10.")[0]
    assert "The main ledger's result is OK." in res


def test_t042_without_a_secondary_finding_the_wording_is_unchanged(env):
    w, signer = env
    a, b = _pair(w, signer)
    md = render_md(build_report(a, public_key_paths=[w / "k.pub"], peer_ledgers=[b]))
    assert "(main ledger)" not in md and "did not come out clean" not in md
    assert "Verifier status: OK. The checks that were run found no inconsistency in the evidence they covered." in md
