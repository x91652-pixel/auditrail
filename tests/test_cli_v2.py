import json

from auditrail import Guard, KeyRegistry, Ledger, PolicyEngine, ReplayGuard, Signer
from auditrail.cli import main

CFG = {"version": "v", "agents": {"A": {"allowed_tools": ["t"], "tool_categories": {"t": []}},
                                   "B": {"allowed_tools": ["t"], "tool_categories": {"t": []}}}}


def test_keygen_then_signed_anchor_then_verify_with_witness(tmp_path, capsys):
    prefix = tmp_path / "keys" / "rec"
    assert main(["keygen", "--out", str(prefix)]) == 0
    assert main(["keygen", "--out", str(prefix)]) == 1  # refuses to overwrite a private key
    signer = Signer.from_file(str(prefix) + ".key")
    led = Ledger(tmp_path / "l.jsonl", signer=signer)
    guard = Guard(PolicyEngine(CFG), led)
    guard.guarded_tool("t")(lambda: 1)(guard.session("A"))
    guard.heartbeat()
    capsys.readouterr()

    args = ["--anchors", str(tmp_path / "a.jsonl"), "--witness-file", str(tmp_path / "w.jsonl")]
    assert main(["anchor", "--ledger", str(tmp_path / "l.jsonl"), *args, "--key", str(prefix) + ".key"]) == 0
    capsys.readouterr()
    pub = str(prefix) + ".pub"
    code = main(["verify", str(tmp_path / "l.jsonl"), "--pubkey", pub, "--witness-file", str(tmp_path / "w.jsonl"),
                 "--max-gap", "60", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["status"] == "OK" and out["anchored_upto"] == 1 and out["unanchored_tail"] == 0

    # a verifier given a different key must refuse
    other = Signer.generate(); other.save(tmp_path / "other")
    code = main(["verify", str(tmp_path / "l.jsonl"), "--pubkey", str(tmp_path / "other.pub"), "--json"])
    assert code == 1 and json.loads(capsys.readouterr().out)["status"] == "UNKNOWN_KEY"


def test_plain_verify_names_what_it_did_not_check(tmp_path, capsys):
    led = Ledger(tmp_path / "l.jsonl")
    led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={}, decision="allow")
    assert main(["verify", str(tmp_path / "l.jsonl")]) == 0
    out = capsys.readouterr().out
    assert "[OK]" in out and "signatures NOT checked" in out and "no anchors" in out and "heartbeats NOT checked" in out


def test_reconcile_command(tmp_path, capsys):
    a_id, b_id = Signer.generate(), Signer.generate()
    reg = KeyRegistry({"A": a_id.public_hex, "B": b_id.public_hex})
    ga = Guard(PolicyEngine(CFG), Ledger(tmp_path / "a.jsonl"))
    gb = Guard(PolicyEngine(CFG), Ledger(tmp_path / "b.jsonl"))
    s = ga.session("A")
    env = ga.send_message(s, a_id, "B", {"hi": 1})
    gb.receive_message(env, reg, "B", b_id, ReplayGuard())
    assert main(["reconcile", str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl")]) == 0
    assert "1 message(s) recorded by both sides" in capsys.readouterr().out
    # B's record of the message is removed: A's send now has no matching receive
    (tmp_path / "b.jsonl").write_text("", encoding="utf-8")
    assert main(["reconcile", str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl"), "--agent", "A", "--agent", "B"]) == 1
    assert "SEND_WITHOUT_RECV" in capsys.readouterr().out


def test_missing_ledger_is_an_error_not_a_crash(tmp_path, capsys):
    assert main(["verify", str(tmp_path / "nope.jsonl")]) == 2
    assert main(["reconcile", str(tmp_path / "nope.jsonl")]) == 2
