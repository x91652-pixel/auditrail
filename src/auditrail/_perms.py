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

_PS_SCRIPT = (
    "$p = $env:AUDITRAIL_CHECK_PATH; "
    "(Get-Acl -LiteralPath $p).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | "
    "ForEach-Object { $_.IdentityReference.Value + '|' + $_.AccessControlType + '|' + [int64]$_.FileSystemRights }"
)


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
        try:
            entries.append((sid, kind, int(rights)))
        except ValueError:
            continue
    return entries


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
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
            env={**os.environ, "AUDITRAIL_CHECK_PATH": str(p)},
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [Finding("unchecked", f"{p}: permissions NOT CHECKED ({type(exc).__name__}; is PowerShell available?)")]
    if out.returncode != 0:
        return [Finding("unchecked", f"{p}: permissions NOT CHECKED (PowerShell exited {out.returncode})")]
    lines = out.stdout.splitlines()
    if not parse_acl_lines(lines):
        # exit code 0 but nothing we can read: that is "could not check", never "nothing found". Every
        # file has at least one ACE, so an empty result means the listing did not work.
        return [Finding("unchecked", f"{p}: permissions NOT CHECKED (PowerShell succeeded but returned no "
                                     "parseable access-control entries)")]
    return [Finding("loose", f"{p}: {m}") for m in windows_findings(lines, role)]


def permission_warnings(path: Union[str, os.PathLike], role: str) -> list[str]:
    """The messages of permission_findings, for callers that only print."""
    return [f.message for f in permission_findings(path, role)]
