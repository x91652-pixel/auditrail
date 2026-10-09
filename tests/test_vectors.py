"""Conformance vectors (docs/spec/vectors): the Python verifier must give each case's expected result,
and generating them must be deterministic so other implementations can rely on the bytes."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from auditrail.keys import load_public_keys
from auditrail.verifier import verify_all

VECTORS = Path(__file__).resolve().parents[1] / "docs" / "spec" / "vectors"
CASES = sorted(p for p in VECTORS.iterdir() if p.is_dir())


def run_case(case: Path) -> tuple[dict, dict]:
    exp = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    args = exp["args"]
    keys = load_public_keys([case / "recorder.pub"]) if args.get("require_signatures") else None
    got = verify_all(
        case / "ledger.jsonl", public_keys=keys,
        witness_path=case / args["witness"] if args.get("witness") else None,
        max_gap_s=args.get("max_gap_s"),
    )
    return exp, got


def test_there_are_vectors():
    assert len(CASES) >= 10


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_python_verifier_matches_expected(case):
    exp, got = run_case(case)
    for key in ("status", "bad_seq", "anchored_upto", "unanchored_tail"):
        if key in exp:
            assert got.get(key) == exp[key], f"{case.name}: {key}: expected {exp[key]!r}, got {got.get(key)!r} ({got.get('detail')})"


def _snapshot():
    return {str(p.relative_to(VECTORS)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(VECTORS.rglob("*")) if p.is_file() and p.suffix != ".lock"}


def test_generating_the_vectors_is_deterministic():
    before = _snapshot()
    subprocess.run([sys.executable, str(VECTORS / "generate.py")], check=True, capture_output=True)
    assert _snapshot() == before
