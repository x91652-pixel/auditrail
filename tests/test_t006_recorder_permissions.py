"""T-006, decision D-4: the recorder refuses to start when its key (or ledger/anchors) is open to
other accounts, unless told explicitly; a check that could not run is reported, not passed.
"""
import argparse
import os
import queue
import subprocess
import sys
import threading
import warnings
from pathlib import Path

import pytest

from auditrail import Guard, Ledger, PolicyEngine, Signer, ToolDenied
from auditrail import _perms
from auditrail.policy import PolicyError, UnclassifiedToolWarning

ROOT = Path(__file__).resolve().parents[1]


# ====================================================================== D-4: classification

def test_d4_posix_findings_are_classified_loose_not_unchecked():
    f = _perms.classify_findings(_perms.Finding("loose", "mode 0644 gives group/other access"))
    assert f.loose and not f.unchecked


def test_d4_a_missing_file_is_unchecked_not_loose(tmp_path):
    findings = _perms.permission_findings(tmp_path / "nope.key", "secret")
    assert [x.kind for x in findings] == ["unchecked"]
    assert "NOT CHECKED" in findings[0].message


@pytest.mark.skipif(os.name != "nt", reason="needs the Windows ACL path")
def test_d4_powershell_failure_is_unchecked_and_says_so(tmp_path, monkeypatch):
    p = tmp_path / "k.key"
    p.write_text("x")

    def boom(*a, **k):
        raise FileNotFoundError("powershell")

    monkeypatch.setattr(_perms.subprocess, "run", boom)
    findings = _perms.permission_findings(p, "secret")
    assert [x.kind for x in findings] == ["unchecked"]
    assert "NOT CHECKED" in findings[0].message


# ====================================================================== D-4: recorder start-up

def make_args(tmp_path, key, **over):
    base = dict(key=str(key), ledger=str(tmp_path / "l.jsonl"), port=0, policy=None, heartbeat=0, anchors=None,
                anchor_every=None, witness_file=None, git_repo=None, token_env="AUDITRAIL_RECORDER_TOKEN",
                allow_loose_permissions=False)
    base.update(over)
    return argparse.Namespace(**base)


def loosen(path: Path) -> None:
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)  # Everyone
    else:
        path.chmod(0o644)


def tighten(path: Path) -> None:
    if os.name == "nt":
        me = os.environ["USERNAME"]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{me}:(F)"], check=True, capture_output=True)
    else:
        path.chmod(0o600)


def test_d4_serve_refuses_to_start_with_a_loose_key(tmp_path, capsys, monkeypatch):
    from auditrail.recorder import serve

    monkeypatch.setenv("AUDITRAIL_RECORDER_TOKEN", "t")
    key, _ = Signer.generate().save(tmp_path / "rec")
    loosen(key)
    code = serve(make_args(tmp_path, key))
    out = capsys.readouterr().out
    assert code != 0
    assert "REFUSING TO START" in out and "--allow-loose-permissions" in out
    assert not (tmp_path / "l.jsonl").exists(), "nothing may be written before the refusal"


def test_d4_cli_exposes_the_flag_and_defaults_to_refusing():
    from auditrail.cli import build_parser

    parser = build_parser()
    a = parser.parse_args(["recorder", "--ledger", "l", "--key", "k"])
    assert a.allow_loose_permissions is False
    b = parser.parse_args(["recorder", "--ledger", "l", "--key", "k", "--allow-loose-permissions"])
    assert b.allow_loose_permissions is True


def _start_recorder(tmp_path, key, *flags):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "AUDITRAIL_RECORDER_TOKEN": "t", "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "auditrail.cli", "recorder", "--ledger", str(tmp_path / "l.jsonl"), "--key", str(key),
         "--port", "0", "--heartbeat", "0", *flags],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", env=env)
    lines: "queue.Queue[str]" = queue.Queue()
    threading.Thread(target=lambda: [lines.put(x) for x in proc.stdout], daemon=True).start()
    return proc, lines


def _read_until(proc, lines, needle, timeout=30):
    seen = []
    import time
    end = time.time() + timeout
    while time.time() < end:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if proc.poll() is not None and lines.empty():
                break
            continue
        seen.append(line)
        if needle in line:
            return True, seen
    return False, seen


def test_d4_the_flag_downgrades_the_refusal_to_a_warning_and_the_recorder_runs(tmp_path):
    key, _ = Signer.generate().save(tmp_path / "rec")
    loosen(key)
    proc, lines = _start_recorder(tmp_path, key, "--allow-loose-permissions")
    try:
        ok, seen = _read_until(proc, lines, "listening on")
        assert ok, "".join(seen)
        assert any("[WARN]" in x and "loose" in x.lower() for x in seen), "".join(seen)
    finally:
        proc.terminate()
        proc.wait(timeout=20)


def test_d4_a_private_key_starts_normally_without_any_flag(tmp_path):
    key, _ = Signer.generate().save(tmp_path / "rec")
    tighten(key)
    proc, lines = _start_recorder(tmp_path, key)
    try:
        ok, seen = _read_until(proc, lines, "listening on")
        assert ok, "".join(seen)
        assert not any("REFUSING" in x for x in seen)
    finally:
        proc.terminate()
        proc.wait(timeout=20)


def test_d4_a_loose_ledger_is_refused_too(tmp_path, capsys, monkeypatch):
    from auditrail.recorder import serve

    monkeypatch.setenv("AUDITRAIL_RECORDER_TOKEN", "t")
    key, _ = Signer.generate().save(tmp_path / "rec")
    tighten(key)
    ledger = tmp_path / "l.jsonl"
    ledger.write_text("", encoding="utf-8")
    if os.name == "nt":
        subprocess.run(["icacls", str(ledger), "/grant", "*S-1-1-0:(M)"], check=True, capture_output=True)  # Everyone: modify
    else:
        ledger.chmod(0o666)
    code = serve(make_args(tmp_path, key))
    out = capsys.readouterr().out
    assert code != 0 and "REFUSING TO START" in out and "ledger" in out


def test_d4_unchecked_is_reported_but_does_not_block_start(tmp_path, capsys, monkeypatch):
    from auditrail import recorder

    monkeypatch.setenv("AUDITRAIL_RECORDER_TOKEN", "t")
    key, _ = Signer.generate().save(tmp_path / "rec")
    monkeypatch.setattr(recorder, "_permission_findings_for_start",
                        lambda *a, **k: [_perms.Finding("unchecked", f"{key}: permissions NOT CHECKED (PowerShell unavailable)")])
    started = threading.Event()

    def fake_start(self):
        started.set()
        raise KeyboardInterrupt  # end serve() right after "start"

    monkeypatch.setattr(recorder.RecorderService, "start", fake_start)
    with pytest.raises(KeyboardInterrupt):
        recorder.serve(make_args(tmp_path, key))
    out = capsys.readouterr().out
    assert started.is_set()
    assert "NOT CHECKED" in out and "REFUSING" not in out
