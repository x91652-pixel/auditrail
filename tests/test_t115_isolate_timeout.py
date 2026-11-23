"""0.3.4 item 11 (B-F4): the timeout of an isolated tool ends the whole process tree, so it is enforced on time."""
import os
import subprocess
import time

import pytest

from auditrail import Guard, Ledger, PolicyEngine
from fixtures_tools import leave_a_child_and_hang

POL = {"version": "p", "agents": {"a": {"allowed_tools": ["spawn"], "tool_categories": {"spawn": ["internal"]}}},
       "default": {"allowed_tools": []}}


def alive(pid: int) -> bool:
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_a_tool_that_leaves_a_child_holding_the_pipes_still_times_out_on_time_and_the_child_is_killed(tmp_path):
    g = Guard(PolicyEngine(POL), Ledger(tmp_path / "l.jsonl", fsync=False))
    pidfile = tmp_path / "child.pid"
    tool = g.guarded_tool("spawn", categories=["internal"], isolate=True, timeout=2)(leave_a_child_and_hang)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        tool(g.session("a"), str(pidfile))
    took = time.monotonic() - t0
    assert took < 10, f"timeout=2 returned after {took:.1f}s"
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while alive(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not alive(pid), "the child the tool left behind must be killed with the worker"
