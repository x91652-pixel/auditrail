"""0.3.4 item 10 (B-F6): a backslash in ledger text must be escaped in the Markdown report, or it cancels our escapes."""
from auditrail.report import _md_text

BS = chr(92)


def test_a_backslash_is_escaped_so_the_next_escape_survives():
    assert _md_text(BS + "*spoof" + BS + "*") == BS * 2 + BS + "*spoof" + BS * 2 + BS + "*"
    assert _md_text("C:" + BS + "dir") == "C:" + BS * 2 + "dir"


def test_text_without_backslashes_is_unchanged_by_the_new_rule():
    assert _md_text("plain text 1") == "plain text 1"
    assert _md_text("a*b") == "a" + BS + "*b"
