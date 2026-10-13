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
from pathlib import Path
from typing import Union

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


def windows_findings(acl_lines: list[str], role: str) -> list[str]:
    """Findings from `SID|Allow/Deny|rights` lines (see _PS_SCRIPT)."""
    mask = _READ_DATA | _WRITE if role == "secret" else _WRITE
    found: list[str] = []
    for line in acl_lines:
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        sid, kind, rights = parts
        if kind != "Allow" or sid not in _BROAD_SIDS:
            continue
        try:
            bits = int(rights)
        except ValueError:
            continue
        if bits & mask:
            what = "read or modify" if role == "secret" else "modify"
            found.append(f"{_BROAD_SIDS[sid]} can {what} it (often inherited from the parent folder)")
    return found


def permission_warnings(path: Union[str, os.PathLike], role: str) -> list[str]:
    """Warnings for one file; an empty list means nothing suspicious was found (not "safe")."""
    p = Path(path)
    if not p.exists():
        return [f"{p} does not exist, so its permissions could not be checked"]
    if os.name != "nt":
        return [f"{p}: {m}" for m in posix_findings(p.stat().st_mode, role)]
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
            env={**os.environ, "AUDITRAIL_CHECK_PATH": str(p)},
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"{p}: permissions could not be checked ({type(exc).__name__})"]
    if out.returncode != 0:
        return [f"{p}: permissions could not be checked (PowerShell exited {out.returncode})"]
    return [f"{p}: {m}" for m in windows_findings(out.stdout.splitlines(), role)]
