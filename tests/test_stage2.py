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


# ---------------------------------------------------------------------------------------------- F4
import asyncio  # noqa: E402


@pytest.mark.parametrize("exc", [SystemExit(3), KeyboardInterrupt(), asyncio.CancelledError()])
def test_f4_a_base_exception_in_a_tool_is_recorded_counts_toward_the_trifecta_and_propagates(tmp_path, exc):
    guard = make_guard(tmp_path)
    session = guard.session("a")

    def read_then_die():
        raise exc

    reader = guard.guarded_tool("read_private")(read_then_die)
    with pytest.raises(type(exc)):
        reader(session)
    web = guard.guarded_tool("web")(lambda: "page")
    send = guard.guarded_tool("send_out")(lambda: "sent")
    web(session)
    with pytest.raises(ToolDenied):  # the interrupted read counted: data_access + untrusted_input + external_comm
        send(session)
    rows = [r for r in Ledger(tmp_path / "l.jsonl") if r["kind"] == "call"]
    assert [(r["tool"], r["decision"]) for r in rows] == [("read_private", "error"), ("web", "allow"), ("send_out", "deny")]
    assert type(exc).__name__ in rows[0]["reason"]


def test_f4_a_failing_record_does_not_hide_the_original_interrupt(tmp_path):
    flaky = FlakyLedger(Ledger(tmp_path / "l.jsonl", fsync=False))
    guard = make_guard(tmp_path, flaky)

    def interrupted():
        flaky.offline = True
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        guard.guarded_tool("read_private")(interrupted)(guard.session("a"))


# ---------------------------------------------------------------------------------------------- F6
from auditrail.ledger import LedgerTailError  # noqa: E402


def _ledger_with_two_records(tmp_path):
    led = Ledger(tmp_path / "l.jsonl", fsync=False)
    for i in range(2):
        led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=[], args={"i": i},
                   decision="allow")
    return led


def test_f6_a_cut_off_last_line_is_refused_with_guidance_and_the_file_is_left_alone(tmp_path):
    led = _ledger_with_two_records(tmp_path)
    p = tmp_path / "l.jsonl"
    p.write_bytes(p.read_bytes()[:-40])
    before = p.read_bytes()
    with pytest.raises(LedgerTailError) as ei:
        led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=[], args={}, decision="allow")
    msg = str(ei.value)
    assert "cut short" in msg and "will not repair" in msg and "start a new ledger file" in msg
    assert p.read_bytes() == before, "the evidence must not be changed"


def test_f6_a_missing_final_newline_is_refused_not_glued_onto_the_last_record(tmp_path):
    led = _ledger_with_two_records(tmp_path)
    p = tmp_path / "l.jsonl"
    p.write_bytes(p.read_bytes().rstrip(b"\n"))
    before = p.read_bytes()
    with pytest.raises(LedgerTailError):
        led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=[], args={}, decision="allow")
    assert p.read_bytes() == before
    from auditrail.verifier import verify_all

    assert verify_all(p)["status"] == "OK", "the two records are still good evidence"


def test_f6_a_normal_ledger_and_an_empty_file_still_accept_writes(tmp_path):
    led = _ledger_with_two_records(tmp_path)
    led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=[], args={}, decision="allow")
    assert len(list(led)) == 3
    (tmp_path / "new.jsonl").write_bytes(b"")
    Ledger(tmp_path / "new.jsonl", fsync=False).record(agent_id="a", session_id="s", policy_version="p", tool="t",
                                                         categories=[], args={}, decision="allow")


def test_f6_the_recorder_reports_the_refusal_to_the_client(tmp_path):
    from auditrail import RecorderService

    led = _ledger_with_two_records(tmp_path)
    p = tmp_path / "l.jsonl"
    p.write_bytes(p.read_bytes()[:-5])
    svc = RecorderService(led, heartbeat_s=0)
    try:
        reply = svc.handle_request({"op": "event", "kind": "heartbeat", "fields": {"recorder_id": "r", "tools": [], "policy_version": "p", "policy_hash": None, "calls_attempted": 0, "calls_recorded": 0, "interval_s": 60}})
        assert reply["ok"] is False and "LedgerTailError" in reply["error"]
    finally:
        svc._server.server_close()


# ---------------------------------------------------------------------------------------------- F7
import json  # noqa: E402
import socket  # noqa: E402

from auditrail.recorder import (  # noqa: E402
    DEFAULT_CONNECTION_TIMEOUT_S, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_LINE_BYTES, RecorderService)


def _service(tmp_path, **kw):
    return RecorderService(Ledger(tmp_path / "r.jsonl", fsync=False), heartbeat_s=0, **kw).start()


def _closed_by_peer(sock, within=5.0):
    sock.settimeout(within)
    try:
        return sock.recv(1) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        return True
    except socket.timeout:
        return False


def test_f7_the_defaults_are_conservative_and_documented():
    assert DEFAULT_MAX_LINE_BYTES == 1024 * 1024
    assert DEFAULT_CONNECTION_TIMEOUT_S == 300.0 and DEFAULT_MAX_CONNECTIONS == 128
    text = open(__import__("pathlib").Path(__file__).resolve().parents[1] / "SECURITY.md", encoding="utf-8").read()
    for needle in ("max_line_bytes", "connection_timeout_s", "max_connections"):
        assert needle in text, needle


def test_f7_a_line_over_the_limit_closes_the_connection_and_a_normal_request_still_works(tmp_path):
    svc = _service(tmp_path, token="t", max_line_bytes=1000)
    try:
        port = svc.address[1]
        big = socket.create_connection(("127.0.0.1", port))
        big.sendall(b"x" * 5000)  # no newline, no token: never parsed, never buffered beyond the limit
        assert _closed_by_peer(big)
        big.close()
        ok = socket.create_connection(("127.0.0.1", port))
        ok.sendall((json.dumps({"op": "event", "kind": "heartbeat", "fields": {}, "token": "wrong"}) + "\n").encode())
        reply = json.loads(ok.makefile("rb").readline())
        assert reply["ok"] is False and "token" in reply["error"]
        ok.close()
    finally:
        svc.stop()


def test_f7_a_line_exactly_at_the_limit_is_still_served(tmp_path):
    svc = _service(tmp_path, token="t", max_line_bytes=300)
    try:
        base = json.dumps({"op": "call", "token": "wrong", "pad": ""})
        req = json.dumps({"op": "call", "token": "wrong", "pad": "p" * (299 - len(base))}) + "\n"
        assert len(req.encode()) == 300  # the line including its newline is exactly the limit
        s = socket.create_connection(("127.0.0.1", svc.address[1]))
        s.sendall(req.encode())
        assert json.loads(s.makefile("rb").readline())["ok"] is False
        s.close()
    finally:
        svc.stop()


def test_f7_an_idle_connection_is_dropped_after_the_timeout(tmp_path):
    svc = _service(tmp_path, token="t", connection_timeout_s=0.5)
    try:
        s = socket.create_connection(("127.0.0.1", svc.address[1]))
        assert _closed_by_peer(s, within=8.0)
        s.close()
    finally:
        svc.stop()


def test_f7_connections_over_the_limit_are_closed_and_slots_are_given_back(tmp_path):
    svc = _service(tmp_path, token="t", max_connections=2)
    try:
        port = svc.address[1]
        a = socket.create_connection(("127.0.0.1", port))
        b = socket.create_connection(("127.0.0.1", port))
        time.sleep(0.3)
        c = socket.create_connection(("127.0.0.1", port))
        assert _closed_by_peer(c), "the third connection must be refused"
        a.close()
        time.sleep(0.5)
        d = socket.create_connection(("127.0.0.1", port))
        d.sendall((json.dumps({"op": "x", "token": "wrong"}) + "\n").encode())
        assert json.loads(d.makefile("rb").readline())["ok"] is False, "a freed slot is reusable"
        for x in (b, c, d):
            x.close()
    finally:
        svc.stop()


# ---------------------------------------------------------------------------------------------- F9
from auditrail.agent_bridge import AgentMessage, SignatureError, sign_message, verify_message  # noqa: E402


def _good():
    return sign_message("alice", {"x": 1}, "secret").to_dict()


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(sig="é" * 64),
    lambda d: d.update(sig=12345),
    lambda d: d.update(sig=None),
    lambda d: d.update(extra="key"),
    lambda d: d.pop("nonce"),
    lambda d: d.update(ts="soon"),
    lambda d: d.update(ts=None),
    lambda d: d.update(payload={1, 2}),
    lambda d: d.update(sender=["not", "a", "string"]),
])
def test_f9_a_malformed_v1_message_is_a_signature_error_not_a_type_error(mutate):
    d = _good()
    mutate(d)
    with pytest.raises(SignatureError):
        verify_message(d, "secret")


def test_f9_a_good_v1_message_and_a_wrong_secret_behave_as_before():
    assert verify_message(_good(), "secret") == {"x": 1}
    with pytest.raises(SignatureError, match="signature mismatch"):
        verify_message(_good(), "other")
    with pytest.raises(SignatureError):
        verify_message(AgentMessage(**_good()), "other")
