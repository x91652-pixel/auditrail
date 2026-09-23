import pytest

from auditrail.ledger import Ledger
from auditrail.policy import PolicyEngine
from auditrail.sandbox import Guard, ToolDenied
from fixtures_tools import add as add_fn

CONFIG = {
    "version": "test-v1",
    "agents": {
        "bot": {
            "allowed_tools": ["read_data", "read_untrusted", "send_out"],
            "tool_categories": {
                "read_data": ["data_access"],
                "read_untrusted": ["untrusted_input"],
                "send_out": ["external_comm"],
            },
            "enforce_lethal_trifecta": True,
            "trifecta_exempt_tools": [],
        }
    },
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}


@pytest.fixture
def guard(tmp_path):
    policy = PolicyEngine(CONFIG)
    ledger = Ledger(tmp_path / "l.jsonl")
    return Guard(policy, ledger)


def test_allowed_call_executes_the_real_function_and_logs_it(guard):
    calls = []

    @guard.guarded_tool("read_data", categories=["data_access"])
    def read_data(x):
        calls.append(x)
        return {"got": x}

    session = guard.session("bot")
    result = read_data(session, "hello")
    assert result == {"got": "hello"}
    assert calls == ["hello"]  # the real function really ran

    records = list(guard.ledger)
    assert len(records) == 1
    assert records[0]["decision"] == "allow"
    assert records[0]["tool"] == "read_data"


def test_denied_call_never_executes_the_real_function(guard):
    calls = []

    @guard.guarded_tool("read_data", categories=["data_access"])
    def read_data(x):
        calls.append(x)
        return {"got": x}

    @guard.guarded_tool("read_untrusted", categories=["untrusted_input"])
    def read_untrusted():
        return "attacker text"

    @guard.guarded_tool("send_out", categories=["external_comm"])
    def send_out(x):
        calls.append(("SENT", x))
        return {"sent": x}

    session = guard.session("bot")
    read_data(session, "hi")
    read_untrusted(session)

    with pytest.raises(ToolDenied):
        send_out(session, "leak")

    assert ("SENT", "leak") not in calls  # the dangerous call never ran

    records = list(guard.ledger)
    assert records[-1]["decision"] == "deny"
    assert "lethal_trifecta" in records[-1]["reason"]


def test_on_deny_return_none_mode(guard):
    @guard.guarded_tool("read_data", categories=["data_access"])
    def read_data(x):
        return x

    @guard.guarded_tool("read_untrusted", categories=["untrusted_input"])
    def read_untrusted():
        return "x"

    @guard.guarded_tool("send_out", categories=["external_comm"], on_deny="return_none")
    def send_out(x):
        return x

    session = guard.session("bot")
    read_data(session, 1)
    read_untrusted(session)
    result = send_out(session, "leak")
    assert result is None


def test_isolated_call_runs_in_subprocess_and_still_returns_real_result(guard):
    guarded_add = guard.guarded_tool("read_data", categories=["data_access"], isolate=True, timeout=10)(add_fn)

    session = guard.session("bot")
    assert guarded_add(session, 2, 3) == 5
    records = list(guard.ledger)
    assert records[0]["decision"] == "sandboxed"


def test_isolate_rejects_local_closures_at_decoration_time(guard):
    def local_fn(a, b):
        return a + b

    with pytest.raises(TypeError):
        guard.guarded_tool("read_data", categories=["data_access"], isolate=True)(local_fn)
