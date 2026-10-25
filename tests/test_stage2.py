"""Stage 2 review findings (recorder and policy): parallel calls, heartbeats, BaseException, torn tail, limits."""
import threading
import time

import pytest

from auditrail import Guard, Ledger, PolicyEngine
from auditrail.sandbox import ToolDenied

CONFIG = {
    "version": "stage2",
    "agents": {"a": {"allowed_tools": ["read_private", "web", "send_out"],
                     "tool_categories": {"read_private": ["data_access"], "web": ["untrusted_input"],
                                         "send_out": ["external_comm"]}}},
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}


def make_guard(tmp_path, ledger=None):
    return Guard(PolicyEngine(CONFIG), ledger or Ledger(tmp_path / "l.jsonl", fsync=False))


# ---------------------------------------------------------------------------------------------- F1
def test_f1_parallel_calls_in_one_session_cannot_complete_the_trifecta(tmp_path):
    """Three tools admitted at the same time used to see an empty history and all run. Admission now reserves the
    categories atomically, so exactly one of the three is refused whatever the interleaving."""
    guard = make_guard(tmp_path)
    session = guard.session("a")
    release = threading.Event()
    entered = []
    outcome = {}

    def body(name):
        def fn():
            entered.append(name)
            release.wait(10)
            return name
        return fn

    tools = {n: guard.guarded_tool(n, on_deny="raise")(body(n)) for n in ("read_private", "web", "send_out")}

    def run(name):
        try:
            outcome[name] = ("allow", tools[name](session))
        except ToolDenied as exc:
            outcome[name] = ("deny", str(exc))

    threads = [threading.Thread(target=run, args=(n,)) for n in tools]
    for t in threads:
        t.start()
    deadline = time.monotonic() + 10
    while len(entered) + sum(1 for v in outcome.values() if v[0] == "deny") < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    release.set()
    for t in threads:
        t.join(10)
    kinds = sorted(v[0] for v in outcome.values())
    assert kinds == ["allow", "allow", "deny"], outcome
    denied = [v for v in outcome.values() if v[0] == "deny"][0][1]
    assert "lethal_trifecta" in denied
    assert len(entered) == 2, "the refused tool must not have run"
