"""0.3.3 B1: `recorder --policy` with a policy that cannot be loaded ends with one clean line on stderr and exit 2."""
import argparse

import pytest

from auditrail import Signer, recorder

ENV = "T103_TOKEN"


def args(tmp_path, key, policy):
    return argparse.Namespace(
        key=str(key), ledger=str(tmp_path / "l.jsonl"), port=0, policy=str(policy), heartbeat=0, anchors=None,
        anchor_every=None, witness_file=None, git_repo=None, token_env=ENV, allow_loose_permissions=True)


@pytest.fixture
def key(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, "t")
    k, _ = Signer.generate().save(tmp_path / "rec")
    return k


@pytest.mark.parametrize("name,text", [
    ("bad-yaml.yaml", "a: b: c\n"),
    ("no-version.yaml", "agents: {}\n"),
    ("bomb.yaml", "version: v1\nx0: &a0 [" + ", ".join(["lol"] * 10) + "]\n"
     + "".join(f"x{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]\n" for i in range(1, 7))),
])
def test_unloadable_policy_is_a_clean_error_and_exit_2(tmp_path, capsys, key, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    code = recorder.serve(args(tmp_path, key, p))
    cap = capsys.readouterr()
    assert code == 2
    assert "Traceback" not in cap.err + cap.out
    lines = [ln for ln in cap.err.splitlines() if ln.strip()]
    assert len(lines) == 1 and lines[0].startswith("[RECORDER][ERROR]") and str(p) in lines[0], cap.err
    assert not (tmp_path / "l.jsonl").exists(), "nothing may be written before the refusal"


def test_missing_policy_file_is_a_clean_error_and_exit_2(tmp_path, capsys, key):
    code = recorder.serve(args(tmp_path, key, tmp_path / "nope.yaml"))
    cap = capsys.readouterr()
    assert code == 2 and cap.err.startswith("[RECORDER][ERROR]") and "Traceback" not in cap.err
