"""C-3: the recorder starts without a token (it always did) but says so, in plain words, for both
shapes of "no token": the variable is not set, and the variable is set to an empty string."""
import argparse

import pytest

from auditrail import RecorderService, Signer, recorder

ENV = "AUDITRAIL_RECORDER_TOKEN"


def args(tmp_path, key, token_env=ENV):
    return argparse.Namespace(
        key=str(key), ledger=str(tmp_path / "l.jsonl"), port=0, policy=None, heartbeat=0, anchors=None,
        anchor_every=None, witness_file=None, git_repo=None, token_env=token_env, allow_loose_permissions=True)


@pytest.fixture
def started(monkeypatch):
    """Capture the service at start() and end serve() right there, so nothing blocks."""
    seen = {}

    def fake_start(self):
        seen["token"] = self.token
        seen["started"] = True
        raise KeyboardInterrupt

    monkeypatch.setattr(RecorderService, "start", fake_start)
    return seen


def run_serve(tmp_path, capsys):
    key, _ = Signer.generate().save(tmp_path / "rec")
    with pytest.raises(KeyboardInterrupt):
        recorder.serve(args(tmp_path, key))
    return capsys.readouterr().out


def test_token_variable_not_set_warns_and_still_starts(tmp_path, capsys, monkeypatch, started):
    monkeypatch.delenv(ENV, raising=False)
    out = run_serve(tmp_path, capsys)
    assert started.get("started") is True
    assert started["token"] is None
    assert "[RECORDER][WARN] no token" in out
    assert "any local process that can reach the port can write to the ledger" in out
    assert "set but empty" not in out


def test_token_variable_set_to_an_empty_string_says_so_warns_and_still_starts(tmp_path, capsys, monkeypatch, started):
    monkeypatch.setenv(ENV, "")
    out = run_serve(tmp_path, capsys)
    assert started.get("started") is True
    assert started["token"] is None, "an empty string must not be accepted as a token"
    assert f"[RECORDER][WARN] {ENV} is set but empty; running WITHOUT a token" in out
    assert "[RECORDER][WARN] no token" in out


def test_a_real_token_produces_no_token_warning(tmp_path, capsys, monkeypatch, started):
    monkeypatch.setenv(ENV, "a-real-token")
    out = run_serve(tmp_path, capsys)
    assert started["token"] == "a-real-token"
    assert "no token" not in out and "set but empty" not in out


def test_the_listening_line_names_the_token_state(tmp_path, monkeypatch):
    """The line printed once the service is up says token=required or NOT set (checked via a real service)."""
    import subprocess
    import sys

    monkeypatch.delenv(ENV, raising=False)
    key, _ = Signer.generate().save(tmp_path / "rec")
    import os
    import time
    env = {k: v for k, v in os.environ.items() if k != ENV}
    env["PYTHONPATH"] = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-m", "auditrail.cli", "recorder", "--ledger", str(tmp_path / "l.jsonl"), "--key", str(key),
         "--port", "0", "--heartbeat", "0", "--allow-loose-permissions"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", env=env)
    try:
        lines = []
        end = time.time() + 30
        while time.time() < end:
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line)
            if "listening on" in line:
                break
        text = "".join(lines)
        assert "token=NOT set" in text and "[RECORDER][WARN] no token" in text, text
    finally:
        proc.kill()
        proc.wait(timeout=10)
