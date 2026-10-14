"""T-019: when PowerShell fails the message must say why (first 300 characters of stderr, control characters
removed), and the failure must still be fail-closed ('unchecked', which the recorder refuses by default)."""
import os
import subprocess

import pytest

from auditrail import _perms


def test_clean_stderr_removes_control_characters_collapses_space_and_truncates():
    raw = "line one\r\nline\ttwo\x00\x1b[31mred\x1b[0m   " + "x" * 400
    out = _perms.clean_stderr(raw)
    assert len(out) <= 300
    assert all(32 <= ord(c) < 127 or ord(c) > 159 for c in out), repr(out)
    assert out.startswith("line one line two") and "\x1b" not in out and "  " not in out


def test_clean_stderr_of_nothing_is_empty():
    assert _perms.clean_stderr("") == "" and _perms.clean_stderr(None) == ""


@pytest.fixture
def keyfile(tmp_path):
    p = tmp_path / "k.key"
    p.write_text("x")
    return p


def _run_returning(code, stdout="", stderr=""):
    return lambda *a, **k: subprocess.CompletedProcess(a, code, stdout=stdout, stderr=stderr)


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_a_failing_powershell_puts_its_stderr_in_the_message_and_stays_unchecked(keyfile, monkeypatch):
    err = "Get-Acl : The 'Get-Acl' command was found in the module 'Microsoft.PowerShell.Security'\r\n" + "z" * 500
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(1, stderr=err))
    findings = _perms.permission_findings(keyfile, "secret")
    assert [f.kind for f in findings] == ["unchecked"], "failure must stay fail-closed"
    msg = findings[0].message
    assert "PowerShell exited 1" in msg and "NOT CHECKED" in msg
    assert "Get-Acl : The 'Get-Acl' command was found" in msg
    assert "\r" not in msg and "\n" not in msg
    assert msg.count("z") <= 300


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_exit_zero_with_nothing_parseable_also_carries_stderr(keyfile, monkeypatch):
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(0, stdout="", stderr="WARNING: something odd"))
    findings = _perms.permission_findings(keyfile, "secret")
    assert [f.kind for f in findings] == ["unchecked"]
    assert "WARNING: something odd" in findings[0].message


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_the_script_reports_a_thrown_error_on_stderr_and_exits_non_zero(tmp_path):
    """Runs the real script against a path that does not exist: it must fail loudly (stderr + exit 1), not print
    nothing, so that a runner where it fails shows a reason."""
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _perms._PS_SCRIPT],
        env={**os.environ, "AUDITRAIL_CHECK_PATH": str(tmp_path / "does-not-exist")},
        capture_output=True, text=True, timeout=60)
    assert out.returncode != 0
    assert out.stderr.strip(), "no explanation on stderr"
    assert out.stdout.strip() == ""
