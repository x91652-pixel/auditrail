"""0.3.4 items 5-8 (A-F3..F6): unreadable inputs give a clean error and exit 2; no KeyError; no OK for a missing ledger."""
import pytest

from auditrail import Ledger, Signer
from auditrail.cli import main
from auditrail.verifier import verify_all


def _ledger(tmp_path):
    p = tmp_path / "l.jsonl"
    Ledger(p, signer=Signer.from_seed(bytes([9]) * 32)).record(
        agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={}, decision="allow")
    return p


@pytest.mark.parametrize("cmd", ["verify", "reconcile"])
def test_item5_an_unreadable_ledger_is_exit_2_with_one_error_line(tmp_path, capsys, monkeypatch, cmd):
    p = _ledger(tmp_path)
    real = type(p).read_bytes

    def deny(self):
        if self.name == "l.jsonl":
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr(type(p), "read_bytes", deny)
    code = main([cmd, str(p)])
    cap = capsys.readouterr()
    assert code == 2 and "Traceback" not in cap.err + cap.out
    assert cap.err.startswith("[ERROR]") and "Permission denied" in cap.err and len(cap.err.strip().splitlines()) == 1


@pytest.mark.parametrize("argv", [
    lambda t, p: ["anchor", "--ledger", str(p), "--anchors", str(t / "a.jsonl"), "--key", str(t / "nope.key")],
])
def test_item6_anchor_with_a_missing_key_is_exit_2(tmp_path, capsys, argv):
    p = _ledger(tmp_path)
    assert main(argv(tmp_path, p)) == 2
    cap = capsys.readouterr()
    assert "Traceback" not in cap.err + cap.out and "[ERROR]" in cap.err + cap.out


def test_item6_anchor_with_a_malformed_key_is_exit_2(tmp_path, capsys):
    p = _ledger(tmp_path)
    k = tmp_path / "bad.key"
    k.write_text("abcd\n")
    assert main(["anchor", "--ledger", str(p), "--anchors", str(tmp_path / "a.jsonl"), "--key", str(k)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_item6_recorder_with_a_missing_key_is_exit_2(tmp_path, capsys, monkeypatch):
    import argparse
    from auditrail import recorder

    monkeypatch.setenv("T115_TOKEN", "t")
    ns = argparse.Namespace(key=str(tmp_path / "nope.key"), ledger=str(tmp_path / "l.jsonl"), port=0, policy=None,
                            heartbeat=0, anchors=None, anchor_every=None, witness_file=None, git_repo=None,
                            token_env="T115_TOKEN", allow_loose_permissions=True)
    assert recorder.serve(ns) == 2
    cap = capsys.readouterr()
    assert "Traceback" not in cap.err and "[RECORDER][ERROR]" in cap.err


def test_item7_ledger_verify_does_not_raise_on_legacy_or_non_utf8(tmp_path):
    legacy = tmp_path / "legacy.jsonl"
    legacy.write_text('{"seq":0,"agent_id":"a"}\n', encoding="utf-8")
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(b"\xff\xfe\x00 not utf-8\n")
    for p in (legacy, bad):
        ok, seq = Ledger(p).verify()
        assert ok is False and seq is None


def test_item8_verify_all_on_a_missing_ledger_is_an_error_not_ok(tmp_path):
    with pytest.raises(FileNotFoundError):
        verify_all(tmp_path / "does-not-exist.jsonl")
