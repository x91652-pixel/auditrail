"""T-020: the Windows ACL check must not depend on the PowerShell module system or on the parent's PSModulePath.

CI showed: pytest started from PowerShell 7, child powershell.exe 5.1 -> "The 'Get-Acl' command was found in the
module 'Microsoft.PowerShell.Security', but the module could not be loaded". Three measures, tested here:
A. the child gets an environment without PSModulePath   B. 5.1 is started by its system path
C. the script uses .NET calls only (no Get-Acl / Test-Path / other module cmdlets)
"""
import os
import re
import subprocess

import pytest

from auditrail import _perms

WINDOWS = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell")


# ---------------------------------------------------------------- A

@pytest.mark.parametrize("name", ["PSModulePath", "PSMODULEPATH", "psmodulepath"])
def test_a_the_child_environment_has_no_psmodulepath_in_any_case(monkeypatch, name):
    for k in list(os.environ):
        if k.upper() == "PSMODULEPATH":
            monkeypatch.delenv(k)
    monkeypatch.setenv("KEEP_ME", "1")
    env = {k: v for k, v in _perms.powershell_environment("C:\\x").items()}
    assert not any(k.upper() == "PSMODULEPATH" for k in env)
    assert env["KEEP_ME"] == "1" and env["AUDITRAIL_CHECK_PATH"] == "C:\\x"
    monkeypatch.setenv(name, "C:\\Program Files\\PowerShell\\7\\Modules")
    env = _perms.powershell_environment("C:\\y")
    assert not any(k.upper() == "PSMODULEPATH" for k in env), "inherited PS7 module path must not be passed on"
    assert env["AUDITRAIL_CHECK_PATH"] == "C:\\y"


@WINDOWS
def test_a_and_b_permission_findings_hands_subprocess_the_isolated_environment_and_system_exe(tmp_path, monkeypatch):
    p = tmp_path / "k.key"
    p.write_text("x")
    monkeypatch.setenv("PSModulePath", "C:\\Program Files\\PowerShell\\7\\Modules")
    seen = {}

    def fake_run(args, **kw):
        seen["args"], seen["env"] = args, kw.get("env")
        return subprocess.CompletedProcess(args, 0, stdout="S-1-5-18|Allow|2032127\n", stderr="")

    monkeypatch.setattr(_perms.subprocess, "run", fake_run)
    assert _perms.permission_findings(p, "secret") == []
    assert seen["args"][0] == _perms.powershell_executable()
    assert not any(k.upper() == "PSMODULEPATH" for k in seen["env"])
    assert seen["env"]["AUDITRAIL_CHECK_PATH"] == str(p)


# ---------------------------------------------------------------- B

@WINDOWS
def test_b_powershell_is_started_by_its_system_path():
    exe = _perms.powershell_executable()
    assert os.path.isabs(exe) and exe.lower().endswith(os.path.join("v1.0", "powershell.exe").lower())
    assert os.path.isfile(exe)


def test_b_falls_back_to_the_bare_name_when_the_system_file_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setenv("windir", str(tmp_path))
    assert _perms.powershell_executable() == "powershell"


# ---------------------------------------------------------------- C

def test_c_the_script_calls_no_module_cmdlets():
    script = _perms._PS_SCRIPT
    assert "Get-Acl" not in script and "Test-Path" not in script
    assert re.search(r"\b(Get|Set|Test|Import|New)-[A-Z]", script) is None, "no verb-noun cmdlets at all"
    assert "$env:" not in script, "the Env: drive is a provider too; use [Environment]"
    assert "GetAccessControl" in script


@WINDOWS
def test_c_the_script_still_works_when_get_acl_is_unusable(tmp_path):
    """Reproduces 'the Get-Acl command could not be loaded' without PowerShell 7: shadow Get-Acl with a function
    that throws. A script that used Get-Acl fails here; the .NET-only script is unaffected."""
    p = tmp_path / "k.key"
    p.write_text("x")
    script = "function Get-Acl { throw 'the module could not be loaded' }; " + _perms._PS_SCRIPT
    out = subprocess.run([_perms.powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", script],
                         env=_perms.powershell_environment(str(p)), capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    entries = _perms.parse_acl_lines(out.stdout.splitlines())
    assert entries and all(sid.startswith("S-") for sid, _, _ in entries)


@WINDOWS
def test_c_a_junk_inherited_psmodulepath_does_not_make_the_check_fail(tmp_path, monkeypatch):
    p = tmp_path / "k.key"
    p.write_text("x")
    monkeypatch.setenv("PSModulePath", "C:\\definitely\\not\\there;C:\\Program Files\\PowerShell\\7\\Modules")
    kinds = [f.kind for f in _perms.permission_findings(p, "secret")]
    assert "unchecked" not in kinds, kinds


@WINDOWS
def test_c_directories_are_handled_by_the_same_script(tmp_path):
    kinds = [f.kind for f in _perms.permission_findings(tmp_path, "writable")]
    assert "unchecked" not in kinds, kinds


@WINDOWS
def test_c_a_missing_path_still_fails_loudly_with_a_reason(tmp_path):
    out = subprocess.run([_perms.powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", _perms._PS_SCRIPT],
                         env=_perms.powershell_environment(str(tmp_path / "nope")), capture_output=True, text=True,
                         timeout=60)
    assert out.returncode != 0 and out.stderr.strip() and out.stdout.strip() == ""
