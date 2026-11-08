"""The README's "Wrap a tool function" snippet is extracted and run, so README and API cannot drift apart."""
import re
import subprocess
import sys
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"
MARKER = "Wrap a tool function"


def snippet() -> str:
    text = README.read_text(encoding="utf-8")
    start = text.index(MARKER)
    m = re.search(r"```python\n(.*?)```", text[start:], re.S)
    assert m, "no python block after the 'Wrap a tool function' line in README.md"
    return m.group(1)


def test_wrap_a_tool_function_snippet_runs_and_the_ledger_verifies(tmp_path):
    (tmp_path / "snippet.py").write_text(snippet(), encoding="utf-8")
    run = subprocess.run([sys.executable, "snippet.py"], cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    assert "cand-001" in run.stdout
    ledger = tmp_path / "evidence.jsonl"
    assert ledger.is_file() and ledger.read_text(encoding="utf-8").strip(), "the snippet must write evidence.jsonl"
    from auditrail.cli import main

    assert main(["verify", str(ledger)]) == 0
