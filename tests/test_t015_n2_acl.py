"""T-015 N-2: a Windows ACL check that succeeded with no usable output was read as 'nothing wrong' (fail-open).
"""
import argparse
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from auditrail import Guard, Ledger, PolicyEngine, Signer, _perms, recorder
from auditrail.policy import PolicyError

SRC = Path(__file__).resolve().parents[1] / "src" / "auditrail"




# ============================================================ N-2

def test_n2_parser_counts_only_real_entries():
    good = "S-1-5-21-1|Allow|268435456\nS-1-1-0|Deny|1"
    assert len(_perms.parse_acl_lines(good.splitlines())) == 2
    for junk in ([], [""], ["   "], ["IdentityReference|AccessControlType|FileSystemRights"],
                 ["not an acl"], ["a|b"], ["S-1|Maybe|1"], ["S-1|Allow|notanumber"], ["|Allow|1"]):
        assert _perms.parse_acl_lines(junk) == [], junk


def _fake_run(stdout, code=0):
    return lambda *a, **k: subprocess.CompletedProcess(a, code, stdout=stdout, stderr="")


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
@pytest.mark.parametrize("stdout", ["", "\n\n", "   \n", "garbage output\nmore garbage",
                                    "IdentityReference|AccessControlType|FileSystemRights\n"],
                         ids=["empty", "blank-lines", "spaces", "garbage", "header-only"])
def test_n2_exit_zero_without_a_parseable_acl_is_unchecked_not_fine(tmp_path, monkeypatch, stdout):
    p = tmp_path / "k.key"
    p.write_text("x")
    monkeypatch.setattr(_perms.subprocess, "run", _fake_run(stdout))
    findings = _perms.permission_findings(p, "secret")
    assert [f.kind for f in findings] == ["unchecked"]
    assert "NOT CHECKED" in findings[0].message


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_n2_a_real_acl_listing_without_broad_groups_is_still_clean(tmp_path, monkeypatch):
    p = tmp_path / "k.key"
    p.write_text("x")
    monkeypatch.setattr(_perms.subprocess, "run", _fake_run("S-1-5-21-1-2-3-1001|Allow|2032127\n"))
    assert _perms.permission_findings(p, "secret") == []


@pytest.mark.skipif(os.name != "nt", reason="the ACL path is Windows-only")
def test_n2_the_recorder_refuses_to_start_and_the_flag_downgrades_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AUDITRAIL_RECORDER_TOKEN", "t")
    key, _ = Signer.generate().save(tmp_path / "rec")
    monkeypatch.setattr(_perms.subprocess, "run", _fake_run(""))

    def ns(allow):
        return argparse.Namespace(key=str(key), ledger=str(tmp_path / "l.jsonl"), port=0, policy=None, heartbeat=0,
                                  anchors=None, anchor_every=None, witness_file=None, git_repo=None,
                                  token_env="AUDITRAIL_RECORDER_TOKEN", allow_loose_permissions=allow)

    def fake_start(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(recorder.RecorderService, "start", fake_start)
    try:
        code = recorder.serve(ns(False))
    except KeyboardInterrupt:
        pytest.fail("the recorder started although the permission check produced nothing")
    out = capsys.readouterr().out
    assert code == 2 and "REFUSING TO START" in out and "NOT CHECKED" in out
    with pytest.raises(KeyboardInterrupt):
        recorder.serve(ns(True))
    assert "[RECORDER][WARN] NOT CHECKED" in capsys.readouterr().out
