"""SqliteReplayGuard closes every connection it opens (no leak, no ResourceWarning on newer Pythons)."""
import sqlite3

import pytest

from auditrail.agent_bridge import SqliteReplayGuard


def _track(monkeypatch):
    opened = []
    real = SqliteReplayGuard._connect

    def tracking(self):
        conn = real(self)
        opened.append(conn)
        return conn

    monkeypatch.setattr(SqliteReplayGuard, "_connect", tracking)
    return opened


def _is_closed(conn):
    try:
        conn.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


def test_construction_and_use_leave_no_open_connection(tmp_path, monkeypatch):
    opened = _track(monkeypatch)
    guard = SqliteReplayGuard(tmp_path / "r.db")
    assert guard.seen_before("n1") is False
    assert guard.seen_before("n1") is True
    assert len(opened) >= 2
    assert all(_is_closed(c) for c in opened)


def test_a_failing_construction_still_closes_the_connection(tmp_path, monkeypatch):
    opened = _track(monkeypatch)
    (tmp_path / "bad.db").write_bytes(b"this is not a sqlite database" * 20)
    with pytest.raises(sqlite3.Error):
        SqliteReplayGuard(tmp_path / "bad.db")
    assert opened and all(_is_closed(c) for c in opened)
