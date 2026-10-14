"""T-010b, D-10: when the permission check cannot run, the recorder refuses to start (exit 2) unless
--allow-loose-permissions is given, in which case it prints NOT CHECKED and starts. Also D-8 (2):
a ledger or anchors file that others can write is refused, with the flag to downgrade it.

The "cannot run" condition is produced by monkeypatching, never by removing PowerShell.
"""
import argparse
import os
import subprocess
import sys

import pytest

from auditrail import RecorderService, Signer, _perms, recorder

ENV = "AUDITRAIL_RECORDER_TOKEN"


def args(tmp_path, key, anchors=None, allow=False):
    return argparse.Namespace(
        key=str(key), ledger=str(tmp_path / "l.jsonl"), port=0, policy=None, heartbeat=0,
        anchors=str(anchors) if anchors else None, anchor_every=None, witness_file=None, git_repo=None,
        token_env=ENV, allow_loose_permissions=allow)


@pytest.fixture
def key(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, "t")
    k, _ = Signer.generate().save(tmp_path / "rec")
    return k


@pytest.fixture
def started(monkeypatch):
    seen = {}

    def fake_start(self):
        seen["started"] = True
        raise KeyboardInterrupt  # end serve() right after the permission gate

    monkeypatch.setattr(RecorderService, "start", fake_start)
    return seen


def refused(tmp_path, key, **kw):
    """serve() must return 2 without starting; if it starts, the fake start() raises KeyboardInterrupt, which
    would abort the whole pytest session, so turn that into an ordinary failure."""
    try:
        return recorder.serve(args(tmp_path, key, **kw))
    except KeyboardInterrupt:
        pytest.fail("the recorder started although it should have refused")


def cannot_run(monkeypatch, key):
    monkeypatch.setattr(
        recorder, "_permission_findings_for_start",
        lambda *a, **k: [_perms.Finding("unchecked", f"signing key {key}: permissions NOT CHECKED (PowerShell exited 1)")])


# ------------------------------------------------------------------ D-10

def test_d10_unchecked_refuses_to_start_by_default(tmp_path, capsys, monkeypatch, key, started):
    cannot_run(monkeypatch, key)
    code = refused(tmp_path, key)
    out = capsys.readouterr().out
    assert code == 2
    assert not started, "the service must not have been started"
    assert "REFUSING TO START" in out
    assert "NOT CHECKED" in out and "PowerShell exited 1" in out, "the reason must be in the message"
    assert "--allow-loose-permissions" in out
    assert not (tmp_path / "l.jsonl").exists(), "nothing may be written before the refusal"


def test_d10_the_flag_downgrades_it_to_a_not_checked_warning_and_it_starts(tmp_path, capsys, monkeypatch, key, started):
    cannot_run(monkeypatch, key)
    with pytest.raises(KeyboardInterrupt):
        recorder.serve(args(tmp_path, key, allow=True))
    out = capsys.readouterr().out
    assert started.get("started") is True
    assert "[RECORDER][WARN] NOT CHECKED" in out and "REFUSING" not in out


def test_d10_a_missing_key_file_is_not_the_same_as_a_check_that_could_not_run(tmp_path):
    findings = _perms.permission_findings(tmp_path / "absent.key", "secret")
    assert [f.kind for f in findings] == ["missing"]


@pytest.mark.skipif(os.name != "nt", reason="the PowerShell path exists only on Windows")
@pytest.mark.parametrize("failure", ["not_found", "exit_code", "timeout"])
def test_d10_windows_powershell_failures_all_end_in_refusal(tmp_path, capsys, monkeypatch, key, started, failure):
    def fake_run(*a, **k):
        if failure == "not_found":
            raise FileNotFoundError("powershell")
        if failure == "timeout":
            raise subprocess.TimeoutExpired("powershell", 30)
        return subprocess.CompletedProcess(a, 1, stdout="", stderr="boom")

    monkeypatch.setattr(_perms.subprocess, "run", fake_run)
    assert refused(tmp_path, key) == 2
    out = capsys.readouterr().out
    assert "REFUSING TO START" in out and "NOT CHECKED" in out and not started
    with pytest.raises(KeyboardInterrupt):
        recorder.serve(args(tmp_path, key, allow=True))
    assert "[RECORDER][WARN] NOT CHECKED" in capsys.readouterr().out


@pytest.mark.skipif(os.name == "nt", reason="POSIX does not use PowerShell; this pins that it is untouched")
def test_d10_posix_never_asks_powershell(tmp_path, monkeypatch, key):
    def boom(*a, **k):
        raise AssertionError("PowerShell must not be used on POSIX")

    monkeypatch.setattr(_perms.subprocess, "run", boom)
    key_path = tmp_path / "rec.key"
    key_path.chmod(0o600)
    assert _perms.permission_findings(key_path, "secret") == []


# ------------------------------------------------------------------ D-8 (2): anchors and ledger writable by others

def _make_writable_by_everyone(path):
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(M)"], check=True, capture_output=True)
    else:
        path.chmod(0o666)


def test_d8_2_an_anchors_file_others_can_write_is_refused_and_the_flag_downgrades_it(tmp_path, capsys, key, started):
    anchors = tmp_path / "anchors.jsonl"
    anchors.write_text("", encoding="utf-8")
    _make_writable_by_everyone(anchors)
    code = refused(tmp_path, key, anchors=anchors)
    out = capsys.readouterr().out
    assert code == 2 and "REFUSING TO START" in out and "anchors" in out
    assert not started
    with pytest.raises(KeyboardInterrupt):
        recorder.serve(args(tmp_path, key, anchors=anchors, allow=True))
    assert started.get("started") is True
    assert "loose permissions accepted" in capsys.readouterr().out
