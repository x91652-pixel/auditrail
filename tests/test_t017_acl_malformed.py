"""T-017 R-1 (N-4): one readable ACE used to be enough for the Windows check to ignore every line it could
not parse. A line that mentions a broad group but cannot be parsed now makes the whole file 'unchecked'
(the recorder refuses to start unless --allow-loose-permissions, which then prints NOT CHECKED).
"""
import argparse
import os
import subprocess

import pytest

from auditrail import Signer, _perms, recorder

SYSTEM = "S-1-5-18|Allow|2032127"          # a normal, tight entry
EVERYONE_OK = "S-1-1-0|Allow|2032127"       # a well-formed broad entry (reported as loose, not unchecked)

MALFORMED = {
    "rights-not-a-number": "S-1-1-0|Allow|abc",
    "two-columns": "S-1-1-0|Allow",
    "spaces-around-pipes": "S-1-1-0 | Allow | 2032127",
    "lowercase-allow": "S-1-1-0|allow|2032127",
    "hex-rights": "S-1-1-0|Allow|0x1F01FF",
    "four-columns": "S-1-1-0|Allow|2032127|extra",
    "mixed-garbage": "garbage <<S-1-1-0>> ?? Allow ?? 2032127 !!",
    "name-instead-of-sid": "Everyone|Allow|abc",
    "users-sid": "S-1-5-32-545|Allow|0x1",
    "authenticated-users": "S-1-5-11,Allow,1",
    "underscore-number": "S-1-1-0|Allow|2_032_127",
}


# ---------------------------------------------------------------- the pure part (every platform)

@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_r1_a_malformed_line_that_mentions_a_broad_group_is_reported(name):
    lines = [SYSTEM, MALFORMED[name]]
    assert _perms.parse_acl_lines(lines) == [("S-1-5-18", "Allow", 2032127)], "only the good line parses"
    assert _perms.unparsed_broad_lines(lines) == [MALFORMED[name]]


def test_r1_noise_that_mentions_no_broad_group_is_not_reported():
    lines = [SYSTEM, "WARNING: something unrelated", "", "   ", "IdentityReference|AccessControlType|FileSystemRights",
             "C:\\Users\\someone\\file.key", "S-1-5-21-1-2-3-1001|Allow|abc"]
    assert _perms.unparsed_broad_lines(lines) == []


def test_r1_well_formed_lines_are_never_reported_even_for_broad_groups():
    assert _perms.unparsed_broad_lines([SYSTEM, EVERYONE_OK, "S-1-5-32-545|Deny|1"]) == []


def test_r1_every_broad_sid_and_name_in_the_code_is_recognised():
    for sid, name in _perms._BROAD_SIDS.items():
        assert _perms.unparsed_broad_lines([f"{sid}|Allow|x"]) == [f"{sid}|Allow|x"]
        assert _perms.unparsed_broad_lines([f"{name}|Allow|x"]) == [f"{name}|Allow|x"]
        assert _perms.unparsed_broad_lines([f"{name.lower()}|Allow|x"]), "matching ignores case"


# ---------------------------------------------------------------- through permission_findings (Windows)

def _fake_run(stdout):
    return lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=stdout, stderr="")


@pytest.fixture
def keyfile(tmp_path):
    p = tmp_path / "k.key"
    p.write_text("x")
    return p


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_r1_each_malformed_shape_makes_the_file_unchecked(keyfile, monkeypatch, name):
    monkeypatch.setattr(_perms.subprocess, "run", _fake_run(f"{SYSTEM}\n{MALFORMED[name]}\n"))
    findings = _perms.permission_findings(keyfile, "secret")
    assert [f.kind for f in findings] == ["unchecked"], findings
    assert "NOT CHECKED" in findings[0].message


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_r1_a_tight_acl_with_unrelated_noise_still_passes(keyfile, monkeypatch):
    out = f"{SYSTEM}\nS-1-5-32-544|Allow|2032127\nWARNING: unrelated\n\n"
    monkeypatch.setattr(_perms.subprocess, "run", _fake_run(out))
    assert _perms.permission_findings(keyfile, "secret") == []


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_r1_a_well_formed_broad_entry_is_still_loose_not_unchecked(keyfile, monkeypatch):
    monkeypatch.setattr(_perms.subprocess, "run", _fake_run(f"{SYSTEM}\n{EVERYONE_OK}\n"))
    findings = _perms.permission_findings(keyfile, "secret")
    assert [f.kind for f in findings] == ["loose"] and "Everyone" in findings[0].message


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_r1_the_recorder_refuses_on_a_malformed_line_and_the_flag_downgrades_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AUDITRAIL_RECORDER_TOKEN", "t")
    key, _ = Signer.generate().save(tmp_path / "rec")
    monkeypatch.setattr(_perms.subprocess, "run", _fake_run(f"{SYSTEM}\nS-1-1-0|Allow|0x1F01FF\n"))

    def ns(allow):
        return argparse.Namespace(key=str(key), ledger=str(tmp_path / "l.jsonl"), port=0, policy=None, heartbeat=0,
                                  anchors=None, anchor_every=None, witness_file=None, git_repo=None,
                                  token_env="AUDITRAIL_RECORDER_TOKEN", allow_loose_permissions=allow)

    monkeypatch.setattr(recorder.RecorderService, "start", lambda self: (_ for _ in ()).throw(KeyboardInterrupt))
    try:
        code = recorder.serve(ns(False))
    except KeyboardInterrupt:
        pytest.fail("started although an ACL line mentioning Everyone could not be read")
    out = capsys.readouterr().out
    assert code == 2 and "REFUSING TO START" in out and "NOT CHECKED" in out
    with pytest.raises(KeyboardInterrupt):
        recorder.serve(ns(True))
    assert "[RECORDER][WARN] NOT CHECKED" in capsys.readouterr().out
