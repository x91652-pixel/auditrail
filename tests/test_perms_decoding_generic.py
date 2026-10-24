"""PowerShell output that is not plain ASCII is 'unchecked' as a whole, never partly read; Generic rights on a broad
group are loose."""
import os
import subprocess

import pytest

from auditrail import _perms

WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
SYSTEM = "S-1-5-18|Allow|2032127"
EVERYONE = b"S-1-1-0|Allow|2032127"  # Everyone: full control
GOOD = SYSTEM.encode()


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
def test_a_stray_non_ascii_byte_anywhere_makes_the_whole_listing_unchecked(keyfile, monkeypatch):
    """The script prints only ASCII. A byte >= 0x80 means the listing cannot be trusted; it is not skipped line by line."""
    out = GOOD + b"\nS-1-5-32-544|Allow|2032127\nWARNING \x80 noise\n"
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(out))
    findings = _perms.permission_findings(keyfile, "secret")
    assert [f.kind for f in findings] == ["unchecked"] and "not plain ASCII" in findings[0].message


def _hostile_listings():
    """(name, bytes): an Everyone full-control entry that a lenient decoder would damage or hide."""
    cases = {}
    for byte in (b"\xff", b"\x80", b"\x81", b"\xfa", b"\xa4"):
        tag = byte.hex()
        cases[f"inside-sid-{tag}"] = GOOD + b"\n" + b"S" + byte + b"-1-1-0|Allow|2032127" + b"\n"
        cases[f"before-the-S-{tag}"] = GOOD + b"\n" + byte + EVERYONE + b"\n"
        cases[f"after-the-line-{tag}"] = GOOD + b"\n" + EVERYONE + byte + b"\n"
        cases[f"in-the-digits-{tag}"] = GOOD + b"\n" + b"S-1-1-0|Allow|2032" + byte + b"127\n"
        cases[f"on-the-line-before-{tag}"] = GOOD + byte + b"\n" + EVERYONE + b"\n"
        cases[f"on-the-line-after-{tag}"] = EVERYONE + b"\n" + GOOD + byte + b"\n"
    return cases


@WINDOWS_ONLY
@pytest.mark.parametrize("name,listing", sorted(_hostile_listings().items()))
def test_a_non_ascii_byte_next_to_or_inside_an_everyone_entry_never_lets_it_pass(keyfile, monkeypatch, name, listing):
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(listing))
    for role in ("secret", "writable"):
        findings = _perms.permission_findings(keyfile, role)
        assert [f.kind for f in findings] == ["unchecked"], (name, role, findings)


@pytest.mark.parametrize("name,listing", sorted(_hostile_listings().items()))
def test_the_strict_decoder_refuses_every_hostile_listing(name, listing):
    with pytest.raises(_perms.NonAsciiOutput):
        _perms._ascii_listing(listing)


def test_the_strict_decoder_accepts_plain_ascii_none_and_old_style_text():
    assert _perms._ascii_listing(GOOD + b"\r\n" + EVERYONE) == SYSTEM + "\r\n" + EVERYONE.decode()
    assert _perms._ascii_listing(None) == "" and _perms._ascii_listing("S-1-1-0|Allow|1") == "S-1-1-0|Allow|1"
    with pytest.raises(_perms.NonAsciiOutput):
        _perms._ascii_listing("S-1-1-0|Allow|1 é")


@WINDOWS_ONLY
def test_a_pure_ascii_listing_still_passes_and_a_loose_one_is_still_loose(keyfile, monkeypatch):
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(GOOD + b"\nS-1-5-32-544|Allow|2032127\n"))
    assert _perms.permission_findings(keyfile, "secret") == []
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(GOOD + b"\n" + EVERYONE + b"\n"))
    assert [f.kind for f in _perms.permission_findings(keyfile, "secret")] == ["loose"]


@WINDOWS_ONLY
def test_text_output_from_older_fakes_is_still_accepted(keyfile, monkeypatch):
    monkeypatch.setattr(_perms.subprocess, "run", _run_returning(f"{SYSTEM}\nS-1-1-0|Allow|2032127\n"))
    assert [f.kind for f in _perms.permission_findings(keyfile, "secret")] == ["loose"]


def test_decoded_handles_none_bytes_and_text():
    assert _perms._decoded(None) == ""
    assert _perms._decoded("abc") == "abc"
    assert "abc" in _perms._decoded(b"abc\xff")


@pytest.mark.parametrize("rights", [0x80000000, -2147483648, 0x40000000, 0x10000000])
def test_generic_rights_for_everyone_are_loose_on_a_secret(rights):
    assert _perms.windows_findings([f"S-1-1-0|Allow|{rights}"], "secret"), rights


@pytest.mark.parametrize("rights", [0x40000000, 0x10000000])
def test_generic_write_or_all_for_everyone_is_loose_on_a_writable_file(rights):
    assert _perms.windows_findings([f"S-1-1-0|Allow|{rights}"], "writable")


def test_generic_read_alone_is_not_a_write_finding_on_a_writable_file():
    assert _perms.windows_findings(["S-1-1-0|Allow|2147483648"], "writable") == []


def test_generic_execute_for_everyone_is_loose_on_a_secret_but_not_on_a_writable_file():
    assert _perms.windows_findings(["S-1-1-0|Allow|536870912"], "secret")
    assert _perms.windows_findings(["S-1-1-0|Allow|536870912"], "writable") == []


def test_generic_rights_for_a_non_broad_sid_are_ignored():
    assert _perms.windows_findings(["S-1-5-18|Allow|268435456"], "secret") == []
    assert _perms.windows_findings(["S-1-1-0|Deny|268435456"], "secret") == []
