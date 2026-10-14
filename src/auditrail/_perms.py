"""Best-effort check that the files a recorder depends on are not open to other local users.

This produces *warnings only*. It cannot tell who the agent process runs as, and
file permissions do not help if the agent and the recorder are the same OS user
(see SECURITY.md, "Key custody"). What it catches is the cheap mistake: a key file
that every account on the machine can read.

POSIX: mode bits. A "secret" file should have no group/other access at all; a
"writable" file (the ledger, anchors) should not be group/other *writable*.

Windows: mode bits are meaningless there, so the file's ACL is read through
PowerShell (``Get-Acl``) and the entries for broad groups -- Everyone, Users,
Authenticated Users, Guests, Anonymous -- are examined by SID, so the check does
not depend on the system language. A DACL that grants such a group access, usually
by inheritance from the parent folder, is reported. If PowerShell cannot be run,
the check says it could not check; it never reports "fine" in that case.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple, Union

# FileSystemRights bits
_READ_DATA = 0x1 | 0x20  # ReadData, ExecuteFile
_WRITE = 0x2 | 0x4 | 0x10 | 0x40 | 0x10000 | 0x40000 | 0x80000  # write/append/EA/delete-child/delete/change perms/owner

_BROAD_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-7": "Anonymous",
}

# No cmdlets that live in an autoloaded module (Get-Acl, Test-Path, ...): on a runner where pytest is started
# from PowerShell 7, Windows PowerShell 5.1 inherited PS7's module path and failed with "The 'Get-Acl' command
# was found in the module 'Microsoft.PowerShell.Security', but the module could not be loaded". Plain .NET calls
# cannot hit that. The output format is unchanged: one `SID|Allow-or-Deny|rights` line per entry.
_PS_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "try { "
    "$p = [Environment]::GetEnvironmentVariable('AUDITRAIL_CHECK_PATH'); "
    "if ([System.IO.Directory]::Exists($p)) { $sec = [System.IO.Directory]::GetAccessControl($p) } "
    "else { $sec = [System.IO.File]::GetAccessControl($p) }; "
    "$sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | "
    "ForEach-Object { $_.IdentityReference.Value + '|' + $_.AccessControlType + '|' + [int64]$_.FileSystemRights } "
    "} catch { "
    "[Console]::Error.WriteLine($_.Exception.GetType().FullName + ': ' + $_.Exception.Message); exit 1 "
    "}"
)


def powershell_executable() -> str:
    """Windows PowerShell 5.1 by its system path, so a different `powershell` earlier on PATH is not used;
    falls back to the bare name if the system file is not where it should be."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    candidate = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return candidate if os.path.isfile(candidate) else "powershell"


def powershell_environment(path: str) -> dict:
    """The environment for the child: ours, without PSModulePath (so 5.1 computes its own default instead of
    inheriting PowerShell 7's module path), plus the path to check."""
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    env["AUDITRAIL_CHECK_PATH"] = path
    return env


def clean_stderr(text, limit: int = 300) -> str:
    """The start of a stderr text made safe to print: control characters become spaces, runs of whitespace
    collapse, at most `limit` characters. Only what PowerShell said about its own failure; no environment."""
    if not text:
        return ""
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", " ", str(text))  # colour codes
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", text)
    return re.sub(r" {2,}", " ", text).strip()[:limit]


def _failure(p, why: str, stderr) -> "Finding":
    detail = clean_stderr(stderr)
    return Finding("unchecked", f"{p}: permissions NOT CHECKED ({why}{': ' + detail if detail else ''})")


def posix_findings(mode: int, role: str) -> list[str]:
    """Findings for a POSIX mode. role: "secret" (no group/other access) or "writable" (no group/other write)."""
    bits = mode & 0o777
    if role == "secret":
        if bits & 0o077:
            return [f"mode {bits:04o} gives group/other access; a private key should be 0600"]
    elif role == "writable":
        if bits & 0o022:
            return [f"mode {bits:04o} lets group/other write to it; expected 0644 or stricter"]
    else:
        raise ValueError(f"unknown role {role!r}")
    return []


def parse_acl_lines(acl_lines) -> list:
    """The valid `SID|Allow-or-Deny|rights` entries among the lines PowerShell printed, as tuples.

    A line that is not exactly that shape (a header, an error message, blank output) is not an entry.
    """
    entries = []
    for line in acl_lines:
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        sid, kind, rights = parts
        if not sid.startswith("S-") or kind not in ("Allow", "Deny"):
            continue
        if re.fullmatch(r"-?[0-9]+", rights) is None:  # not int(): that accepts "1_0", " 5", "+5"
            continue
        entries.append((sid, kind, int(rights)))
    return entries


_BROAD_PATTERNS = [re.compile(r"(?<![0-9A-Za-z-])" + re.escape(sid) + r"(?![0-9A-Za-z-])", re.I) for sid in _BROAD_SIDS] + [
    re.compile(r"(?<![0-9A-Za-z])" + re.escape(name) + r"(?![0-9A-Za-z])", re.I) for name in _BROAD_SIDS.values()]


def unparsed_broad_lines(acl_lines) -> list:
    """Lines that mention a broad group (its SID or its name) but are not a valid entry.

    The check cannot tell what such a line meant to grant, so a file with one is not 'checked'.
    Blank lines and lines that mention no broad group are ignored: they cannot hide one.
    """
    out = []
    for line in acl_lines:
        if line.strip() and not parse_acl_lines([line]) and any(p.search(line) for p in _BROAD_PATTERNS):
            out.append(line)
    return out


def windows_findings(acl_lines: list[str], role: str) -> list[str]:
    """Findings from `SID|Allow/Deny|rights` lines (see _PS_SCRIPT)."""
    mask = _READ_DATA | _WRITE if role == "secret" else _WRITE
    found: list[str] = []
    for sid, kind, bits in parse_acl_lines(acl_lines):
        if kind != "Allow" or sid not in _BROAD_SIDS:
            continue
        if bits & mask:
            what = "read or modify" if role == "secret" else "modify"
            found.append(f"{_BROAD_SIDS[sid]} can {what} it (often inherited from the parent folder)")
    return found


@dataclass(frozen=True)
class Finding:
    """kind "loose": the file IS open to other accounts. kind "unchecked": the check could not run (no
    PowerShell, it failed, it timed out) -- not a pass; the recorder refuses to start on it unless told
    otherwise. kind "missing": the file does not exist (yet)."""

    kind: str
    message: str


class Classified(NamedTuple):
    loose: list
    unchecked: list


def classify_findings(*findings: Finding) -> Classified:
    return Classified([f for f in findings if f.kind == "loose"], [f for f in findings if f.kind == "unchecked"])


def permission_findings(path: Union[str, os.PathLike], role: str) -> list[Finding]:
    """Findings for one file. An empty list means nothing suspicious was found (not "safe")."""
    p = Path(path)
    if not p.exists():
        return [Finding("missing", f"{p} does not exist, so its permissions are NOT CHECKED")]
    if os.name != "nt":
        return [Finding("loose", f"{p}: {m}") for m in posix_findings(p.stat().st_mode, role)]
    try:
        out = subprocess.run(
            [powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
            env=powershell_environment(str(p)),
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [Finding("unchecked", f"{p}: permissions NOT CHECKED ({type(exc).__name__}; is PowerShell available?)")]
    if out.returncode != 0:
        return [_failure(p, f"PowerShell exited {out.returncode}", out.stderr)]
    lines = out.stdout.splitlines()
    if not parse_acl_lines(lines):
        # exit code 0 but nothing we can read: that is "could not check", never "nothing found". Every
        # file has at least one ACE, so an empty result means the listing did not work.
        return [_failure(p, "PowerShell succeeded but returned no parseable access-control entries", out.stderr)]
    odd = unparsed_broad_lines(lines)
    if odd:
        shown = "; ".join(repr(x[:80]) for x in odd[:3])
        return [Finding("unchecked", f"{p}: permissions NOT CHECKED (PowerShell printed {len(odd)} line(s) that "
                                     f"mention a broad group but could not be parsed: {shown})")]
    return [Finding("loose", f"{p}: {m}") for m in windows_findings(lines, role)]


def permission_warnings(path: Union[str, os.PathLike], role: str) -> list[str]:
    """The messages of permission_findings, for callers that only print."""
    return [f.message for f in permission_findings(path, role)]
