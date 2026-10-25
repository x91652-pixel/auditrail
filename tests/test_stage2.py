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


# ---------------------------------------------------------------------------------------------- F3
class FlakyLedger:
    """A Ledger that can be switched offline, like a recorder that is unreachable for a while."""

    def __init__(self, ledger):
        self._l = ledger
        self.offline = False

    def __getattr__(self, name):
        return getattr(self._l, name)

    def record(self, **kw):
        if self.offline:
            raise OSError("recorder offline")
        return self._l.record(**kw)

    def record_heartbeat(self, **kw):
        if self.offline:
            raise OSError("recorder offline")
        return self._l.record_heartbeat(**kw)


def test_f3_a_failed_heartbeat_does_not_erase_the_count_of_unrecorded_calls(tmp_path):
    from auditrail.verifier import verify_all

    real = Ledger(tmp_path / "l.jsonl", fsync=False)
    flaky = FlakyLedger(real)
    guard = make_guard(tmp_path, flaky)
    work = guard.guarded_tool("web")(lambda: "ok")
    session = guard.session("a")
    guard.heartbeat()  # a first, good heartbeat: the ledger has one
    flaky.offline = True
    for _ in range(3):
        with pytest.raises(OSError):
            work(session)  # the tool ran; its record could not be written
    with pytest.raises(OSError):
        guard.heartbeat()  # fails: the counts it took must be put back
    flaky.offline = False
    guard.heartbeat()
    beats = [r for r in real if r["kind"] == "heartbeat"]
    assert (beats[-1]["calls_attempted"], beats[-1]["calls_recorded"]) == (3, 0)
    assert verify_all(tmp_path / "l.jsonl", max_gap_s=3600)["status"] == "UNRECORDED_CALLS"


def test_f3_the_recorder_service_restores_its_counts_when_the_heartbeat_cannot_be_written(tmp_path):
    from auditrail import RecorderService

    ledger = Ledger(tmp_path / "r.jsonl", fsync=False)
    svc = RecorderService(ledger, heartbeat_s=0)
    try:
        svc._received, svc._written = 5, 2
        real = ledger.record_heartbeat
        ledger.record_heartbeat = lambda **kw: (_ for _ in ()).throw(OSError("disk full"))
        with pytest.raises(OSError):
            svc.heartbeat()
        assert (svc._received, svc._written) == (5, 2)
        ledger.record_heartbeat = real
        rec = svc.heartbeat()
        assert (rec["calls_attempted"], rec["calls_recorded"]) == (5, 2)
        assert (svc._received, svc._written) == (0, 0)
    finally:
        svc._server.server_close()
