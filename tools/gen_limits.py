"""Generate src/auditrail/_limits.py from SECURITY.md.

`auditrail report` prints a fixed "What this report does not prove" section. SECURITY.md is the authority for
that list but is not part of the installed package, so the bold lead sentence of each limit is extracted here,
at build time, and committed as a module together with the SHA-256 of the SECURITY.md text it came from.

    python tools/gen_limits.py            # rewrite src/auditrail/_limits.py
    python tools/gen_limits.py --check    # exit 1 if the committed file differs from what SECURITY.md gives

The parser is strict on purpose: if SECURITY.md is reorganised so that a group disappears or shrinks below its
recorded minimum, this fails instead of quietly producing a shorter list.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "SECURITY.md"
TARGET = ROOT / "src" / "auditrail" / "_limits.py"

# (section heading, [(group label, minimum number of items)]) -- groups in document order
SECTIONS = [
    ("## What v0.2 does NOT do", [("About the evidence", 5), ("About the policy and messages", 4),
                                   ("About isolation", 1), ("About scope", 2)]),
    ("## Where the tests do not reach", [(None, 5)]),
]


class LimitsError(Exception):
    pass


def normalise(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def parse(text: str) -> list[tuple[str, str]]:
    text = normalise(text)
    items: list[tuple[str, str]] = []
    for heading, groups in SECTIONS:
        start = text.find("\n" + heading + "\n")
        if start < 0:
            raise LimitsError(f"SECURITY.md has no section {heading!r}")
        end = text.find("\n## ", start + len(heading) + 2)
        body = text[start:end if end > 0 else len(text)]
        current: str | None = None
        counts: dict = {}
        for line in body.split("\n"):
            m_group = re.fullmatch(r"\*\*(About [^*]+)\*\*", line.strip())
            if m_group:
                current = m_group.group(1)
                continue
            m = re.match(r"- \*\*(.+?)\*\*", line)
            if not m:
                continue
            group = current if groups[0][0] is not None else heading.lstrip("# ")
            items.append((group, m.group(1).strip()))
            counts[group] = counts.get(group, 0) + 1
        for label, minimum in groups:
            key = label if label is not None else heading.lstrip("# ")
            if counts.get(key, 0) < minimum:
                raise LimitsError(f"SECURITY.md: section {heading!r}, group {key!r} has {counts.get(key, 0)} item(s), "
                                  f"expected at least {minimum}")
    return items


def render(text: str) -> str:
    items = parse(text)
    sha = hashlib.sha256(normalise(text).encode("utf-8")).hexdigest()
    lines = ['"""Generated from SECURITY.md by tools/gen_limits.py. Do not edit.', "",
             "The bold lead sentence of every limit in SECURITY.md (\"What v0.2 does NOT do\" and \"Where the tests do not",
             'reach"), and the SHA-256 of the SECURITY.md text (line endings normalised to LF) they were taken from."""',
             "", f"SOURCE_SHA256 = {sha!r}", "", "ITEMS = ("]
    for group, lead in items:
        lines.append(f"    ({group!r}, {lead!r}),")
    lines.append(")")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    wanted = render(SOURCE.read_text(encoding="utf-8"))
    if "--check" in argv:
        have = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if normalise(have) != wanted:
            print(f"{TARGET} is out of date with {SOURCE.name}; run: python tools/gen_limits.py")
            return 1
        print("limits are up to date")
        return 0
    TARGET.write_text(wanted, encoding="utf-8", newline="\n")
    print(f"wrote {TARGET} ({wanted.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
