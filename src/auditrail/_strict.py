"""Strict reading rules shared by every verifier (spec section 2, "Reading files").

Two implementations that disagree about an odd input are a security problem, not a
style problem: an attacker picks the input the weaker reader accepts. These rules
are deliberately narrow so the Rust verifier can match them exactly, and
tests/test_fuzz.py compares the two on mutated and garbage input.

  * Files are UTF-8. Anything else is rejected.
  * Lines are separated by "\\n" only. A trailing "\\r" is ignored. A line holding only
    spaces, tabs and "\\r" is blank and skipped.
  * Each non-blank line is one JSON object. No NaN/Infinity, no floats, no "-0", no integer
    outside the signed 64-bit range, no lone surrogate in any string or key, nesting depth <= 64.
  * Timestamps are YYYY-MM-DDTHH:MM:SSZ with real calendar values, years 1970-9999.
  * Hex fields are lowercase ASCII hex of the exact length.
"""
from __future__ import annotations

import calendar
import json
import re
from typing import Any, Optional

I64_MIN, I64_MAX = -(2 ** 63), 2 ** 63 - 1
MAX_DEPTH = 64

_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX = {64: re.compile(r"[0-9a-f]{64}"), 128: re.compile(r"[0-9a-f]{128}")}


def _reject_number(text: str) -> Any:
    raise ValueError(f"number not allowed in evidence records: {text}")


def _parse_int(text: str) -> int:
    n = int(text)
    if text == "-0" or not (I64_MIN <= n <= I64_MAX):
        raise ValueError(f"integer not allowed in evidence records: {text}")
    return n


def _walk(value: Any, depth: int = 1) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("nesting too deep")
    if isinstance(value, str):
        value.encode("utf-8")  # raises UnicodeEncodeError (a ValueError) for a lone surrogate
    elif isinstance(value, list):
        for v in value:
            _walk(v, depth + 1)
    elif isinstance(value, dict):
        for k, v in value.items():
            k.encode("utf-8")
            _walk(v, depth + 1)


def parse_object(text: str) -> dict:
    """Parse one JSON object under the strict rules. Raises ValueError for anything else."""
    try:
        value = json.loads(text, parse_int=_parse_int, parse_float=_reject_number, parse_constant=_reject_number)
        if not isinstance(value, dict):
            raise ValueError("line is not a JSON object")
        _walk(value)
    except RecursionError as exc:
        raise ValueError("nesting too deep") from exc
    return value


def decode(data: bytes) -> Optional[str]:
    """UTF-8 text, or None when the bytes are not valid UTF-8."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def lines(text: str) -> list[tuple[int, str]]:
    """[(1-based line number, line text)] for non-blank lines, split on "\\n" only."""
    out = []
    for i, line in enumerate(text.split("\n"), 1):
        if line.endswith("\r"):
            line = line[:-1]
        if line.strip(" \t\r") == "":
            continue
        out.append((i, line))
    return out


def is_legacy_text(text: str) -> bool:
    """True when the first non-blank line has no `"format":` member, i.e. a v0.1 ledger (spec section 2).

    A plain substring test on purpose: it needs no JSON parsing, so every implementation gives the same
    answer on every input, including input the strict parser would reject. A v2 record that lost its
    format field also lands here, which is still a non-OK result."""
    for _, line in lines(text):
        return '"format":' not in line
    return False


def parse_ts(ts: Any) -> Optional[int]:
    """Epoch seconds for a valid timestamp string, else None."""
    if not isinstance(ts, str) or _TS.fullmatch(ts) is None:
        return None
    y, mo, d, h, mi, s = int(ts[0:4]), int(ts[5:7]), int(ts[8:10]), int(ts[11:13]), int(ts[14:16]), int(ts[17:19])
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1] if 1 <= mo <= 12 else 0
    if not (1970 <= y <= 9999 and 1 <= mo <= 12 and 1 <= d <= dim and h < 24 and mi < 60 and s < 60):
        return None
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))


def is_int(value: Any) -> bool:
    """A real integer; bool is not one."""
    return type(value) is int


def is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and _HEX[length].fullmatch(value) is not None
