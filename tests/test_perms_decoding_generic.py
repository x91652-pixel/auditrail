"""PowerShell output that cannot be decoded is 'unchecked', not a crash; Generic rights on a broad group are loose."""
import os
import subprocess

import pytest

from auditrail import _perms

WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
SYSTEM = "S-1-5-18|Allow|2032127"


@pytest.fixture
def keyfile(tmp_path):
    p = tmp_path / "k.key"
    p.write_text("x")
    return p


def _run_returning(stdout, stderr=b"", code=0):
    return lambda *a, **k: subprocess.CompletedProcess(a, code, stdout=stdout, stderr=stderr)


@WINDOWS_ONLY
@pytest.mark.parametrize("stdout", [None, b"\xff\xfe\x80\x81 not text", b"\x80\x81\x82", b""])
def test_unreadable_powershell_output_is_unchecked_not_a_traceback(keyfile, monkeypatch, stdout):
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(stdout))
    findings = _perms.permission_findings(keyfile, "secret")
    assert [f.kind for f in findings] == ["unchecked"] and "NOT CHECKED" in findings[0].message


@WINDOWS_ONLY
def test_undecodable_stderr_on_failure_is_unchecked(keyfile, monkeypatch):
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(b"", b"\xff\xfe\x80 failure", code=1))
    findings = _perms.permission_findings(keyfile, "secret")
    assert [f.kind for f in findings] == ["unchecked"] and "PowerShell exited 1" in findings[0].message


@WINDOWS_ONLY
def test_bytes_with_a_good_listing_and_a_stray_undecodable_byte_still_work(keyfile, monkeypatch):
    out = (SYSTEM + "\nS-1-5-32-544|Allow|2032127\nWARNING \x80 noise\n").encode("latin-1")
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(out))
    assert _perms.permission_findings(keyfile, "secret") == []


@WINDOWS_ONLY
def test_text_output_from_older_fakes_is_still_accepted(keyfile, monkeypatch):
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(f"{SYSTEM}\nS-1-1-0|Allow|2032127\n"))
    assert [f.kind for f in _perms.permission_findings(keyfile, "secret")] == ["loose"]


def test_decoded_handles_none_bytes_and_text():
    assert _perms._decoded(None) == ""
    assert _perms._decoded("abc") == "abc"
    assert "abc" in _perms._decoded(b"abc\xff")


@pytest.mark.parametrize("rights", [0x80000000, -2147483648, 0x40000000, 0x10000000])
@pytest.mark.parametrize("role", ["secret"])
def test_generic_rights_for_everyone_are_loose_on_a_secret(rights, role):
    assert _perms.windows_findings([f"S-1-1-0|Allow|{rights}"], role), rights


@pytest.mark.parametrize("rights", [0x40000000, 0x10000000])
def test_generic_write_or_all_for_everyone_is_loose_on_a_writable_file(rights):
    assert _perms.windows_findings([f"S-1-1-0|Allow|{rights}"], "writable")


def test_generic_read_alone_is_not_a_write_finding_on_a_writable_file():
    assert _perms.windows_findings(["S-1-1-0|Allow|2147483648"], "writable") == []


def test_generic_rights_for_a_non_broad_sid_are_ignored():
    assert _perms.windows_findings(["S-1-5-18|Allow|268435456"], "secret") == []
    assert _perms.windows_findings(["S-1-1-0|Deny|268435456"], "secret") == []
