"""The fixed 'does not prove' list is generated from SECURITY.md and locked to it."""
import hashlib
import html as htmllib
import importlib.util
import json
from pathlib import Path

import pytest

from auditrail import _limits
from auditrail.report import LIMITS_FLOOR, build_report, render_html, render_json, render_md

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "SECURITY.md"
COMMITTED = ROOT / "src" / "auditrail" / "_limits.py"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("gen_limits", ROOT / "tools" / "gen_limits.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_limits_equal_what_security_md_gives(gen):
    """Edit SECURITY.md without regenerating (python tools/gen_limits.py) and this fails."""
    committed = COMMITTED.read_text(encoding="utf-8")
    assert gen.normalise(committed) == gen.render(SECURITY.read_text(encoding="utf-8")), (
        "src/auditrail/_limits.py is out of date; run: python tools/gen_limits.py")


def test_the_recorded_hash_is_the_hash_of_security_md_with_lf_endings(gen):
    text = gen.normalise(SECURITY.read_text(encoding="utf-8"))
    assert _limits.SOURCE_SHA256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_changing_security_md_makes_the_committed_file_stale(gen):
    """The red demonstration of the lock: a SECURITY.md edit that is not regenerated no longer matches."""
    text = SECURITY.read_text(encoding="utf-8")
    first = _limits.ITEMS[0][1]
    edited = text.replace(first, first + " (and this was edited)", 1)
    assert edited != text
    committed = gen.normalise(COMMITTED.read_text(encoding="utf-8"))
    assert gen.render(edited) != committed
    # a change outside every bold lead sentence still changes the recorded hash
    assert gen.render(text + "\nA new paragraph.\n") != committed


def test_crlf_checkouts_give_the_same_result(gen):
    text = SECURITY.read_text(encoding="utf-8")
    assert gen.render(text.replace("\n", "\r\n")) == gen.render(text)


def test_the_parser_is_strict_about_structure(gen):
    text = SECURITY.read_text(encoding="utf-8")
    with pytest.raises(gen.LimitsError, match="About scope"):
        gen.parse(text.replace("**About scope**", "**Scope**"))
    with pytest.raises(gen.LimitsError, match="no section"):
        gen.parse(text.replace("## What v0.2 does NOT do", "## What it does not do"))
    with pytest.raises(gen.LimitsError, match="no section"):
        gen.parse(text.replace("## Where the tests do not reach", "## Where tests stop"))
    stripped = "\n".join(line.replace("- **", "- ") for line in text.split("\n") if line.startswith("- **"))
    with pytest.raises(gen.LimitsError):
        gen.parse(text.replace("- **", "- "))
    assert stripped  # (kept simple: removing bold from every bullet removes every item)


def test_every_generated_limit_is_printed_in_every_format(tmp_path):
    (tmp_path / "l.jsonl").write_text("", encoding="utf-8")
    data = build_report(tmp_path / "l.jsonl")
    md, html_, js = render_md(data), render_html(data), json.loads(render_json(data))
    assert len(_limits.ITEMS) >= 20
    assert [x["statement"] for x in js["does_not_prove"]["from_security_md"]] == [s for _, s in _limits.ITEMS]
    for _group, statement in _limits.ITEMS:
        assert htmllib.escape(statement, quote=False) in md
        assert htmllib.escape(statement, quote=True) in html_
    assert _limits.SOURCE_SHA256 in md and _limits.SOURCE_SHA256 in html_
    assert js["does_not_prove"]["security_md_sha256"] == _limits.SOURCE_SHA256


def test_the_floor_does_not_depend_on_the_generated_list(tmp_path, monkeypatch):
    (tmp_path / "l.jsonl").write_text("", encoding="utf-8")
    monkeypatch.setattr(_limits, "ITEMS", ())
    data = build_report(tmp_path / "l.jsonl")
    for sentence in LIMITS_FLOOR:
        assert sentence in render_md(data)
    assert len(LIMITS_FLOOR) == 5
