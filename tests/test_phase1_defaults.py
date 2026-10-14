"""Phase 1: safer defaults that existing users opt into.

(1) strict classification: a wrapped tool with no declared category is refused
(2) the `state_change` category and an optional "after untrusted input" rule
(3) a replay store shared between processes
(4) recorder channel authentication and file-permission warnings
"""
import json
import os
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from auditrail import Guard, KeyRegistry, Ledger, PolicyEngine, Signer, ToolDenied
from auditrail.agent_bridge import (
    ReplayGuard, ReplayStore, SignatureError, SqliteReplayGuard, receive_envelope, send_envelope,
)
from auditrail.policy import PolicyError, UnclassifiedToolWarning

ROOT = Path(__file__).resolve().parents[1]


def cfg(**agent):
    base = {
        "allowed_tools": ["read_feed", "read_db", "send_mail", "mutate", "mystery", "pure"],
        "tool_categories": {
            "read_feed": ["untrusted_input"],
            "read_db": ["data_access"],
            "send_mail": ["external_comm"],
            "mutate": ["state_change"],
            "pure": ["internal"],
        },
    }
    base.update(agent)
    return {"version": "p1", "agents": {"a": base}}


def make_guard(tmp_path, config=None, **engine_kwargs):
    engine = PolicyEngine(config or cfg(), **engine_kwargs)
    ledger = Ledger(tmp_path / "l.jsonl", fsync=False)
    return Guard(engine, ledger), ledger


def tool(guard, name, categories=None, calls=None):
    def fn(*_a, **_k):
        if calls is not None:
            calls.append(name)
        return "ran"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UnclassifiedToolWarning)
        return guard.guarded_tool(name, categories=categories if categories is not None else ())(fn)


# ============================================================ 1. strict classification

def test_strict_refuses_an_unclassified_tool_and_records_why(tmp_path):
    guard, ledger = make_guard(tmp_path, strict=True)
    calls = []
    mystery = tool(guard, "mystery", calls=calls)
    with pytest.raises(ToolDenied) as exc:
        mystery(guard.session("a"))
    assert calls == [], "a refused tool must not run"
    assert "unclassified" in exc.value.reason
    rec = list(ledger)[-1]
    assert rec["decision"] == "deny" and rec["tool"] == "mystery"
    assert rec["reason"].startswith("unclassified_tool")
    assert ledger.verify()[0]


def test_strict_allows_tools_classified_by_decorator_or_policy(tmp_path):
    guard, _ = make_guard(tmp_path, strict=True)
    s = guard.session("a")
    assert tool(guard, "read_db")(s) == "ran"                       # classified in the policy
    assert tool(guard, "mystery", categories=["internal"])(s) == "ran"  # classified at the call site


def test_strict_does_not_accept_an_empty_declaration(tmp_path):
    config = cfg()
    config["agents"]["a"]["tool_categories"]["mystery"] = []  # "I declared nothing"
    guard, _ = make_guard(tmp_path, config, strict=True)
    with pytest.raises(ToolDenied):
        tool(guard, "mystery", categories=[])(guard.session("a"))


def test_strict_can_come_from_the_policy_file_and_kwarg_overrides_it(tmp_path):
    config = cfg()
    config["strict_classification"] = True
    assert PolicyEngine(config).strict is True
    assert PolicyEngine(config, strict=False).strict is False
    assert PolicyEngine(cfg()).strict is False


def test_strict_is_reflected_in_the_policy_hash_but_default_hash_is_unchanged(tmp_path):
    plain = PolicyEngine(cfg()).policy_hash
    assert PolicyEngine(cfg(), strict=False).policy_hash == plain
    assert PolicyEngine(cfg(), strict=True).policy_hash != plain
    config = cfg()
    config["strict_classification"] = True
    assert PolicyEngine(config).policy_hash == PolicyEngine(cfg(), strict=True).policy_hash


def test_non_strict_keeps_the_old_behaviour_but_warns_at_wrap_time(tmp_path):
    guard, ledger = make_guard(tmp_path)
    with pytest.warns(UnclassifiedToolWarning, match="mystery"):
        mystery = guard.guarded_tool("mystery")(lambda *a: "ran")
    assert mystery(guard.session("a")) == "ran"
    assert list(ledger)[-1]["decision"] == "allow"


def test_no_warning_when_the_tool_is_classified_or_strict(tmp_path):
    guard, _ = make_guard(tmp_path)
    with warnings.catch_warnings():
        warnings.simplefilter("error", UnclassifiedToolWarning)
        guard.guarded_tool("read_db")(lambda *a: 1)                          # classified by the policy
        guard.guarded_tool("x", categories=["internal"])(lambda *a: 1)       # classified at the call site
    (tmp_path / "s").mkdir()
    strict_guard, _ = make_guard(tmp_path / "s", strict=True)
    with warnings.catch_warnings():
        warnings.simplefilter("error", UnclassifiedToolWarning)
        strict_guard.guarded_tool("mystery")(lambda *a: 1)  # refused at call time instead; no startup warning


# ============================================================ 2. state_change

def state_cfg(**extra):
    return cfg(enforce_state_change_after_untrusted=True, **extra)


def test_default_policy_evaluates_state_change_exactly_as_before(tmp_path):
    guard, _ = make_guard(tmp_path)  # rule not enabled
    s = guard.session("a")
    tool(guard, "read_feed")(s)
    assert tool(guard, "mutate")(s) == "ran"


def test_state_change_after_untrusted_input_is_refused_when_enabled(tmp_path):
    guard, ledger = make_guard(tmp_path, state_cfg())
    calls = []
    s = guard.session("a")
    tool(guard, "read_feed")(s)
    with pytest.raises(ToolDenied) as exc:
        tool(guard, "mutate", calls=calls)(s)
    assert calls == []
    assert "state_change_after_untrusted" in exc.value.reason
    assert list(ledger)[-1]["decision"] == "deny"


def test_state_change_without_untrusted_input_is_allowed(tmp_path):
    guard, _ = make_guard(tmp_path, state_cfg())
    s = guard.session("a")
    tool(guard, "read_db")(s)
    assert tool(guard, "mutate")(s) == "ran"


def test_explicitly_allowed_state_change_tool_passes(tmp_path):
    guard, _ = make_guard(tmp_path, state_cfg(state_change_allowed_tools=["mutate"]))
    s = guard.session("a")
    tool(guard, "read_feed")(s)
    assert tool(guard, "mutate")(s) == "ran"


def test_state_change_rule_follows_the_workflow_not_just_the_session(tmp_path):
    guard, _ = make_guard(tmp_path, state_cfg())
    s1 = guard.session("a", trace_id="wf-1")
    tool(guard, "read_feed")(s1)
    s2 = guard.session("a", trace_id="wf-1")
    with pytest.raises(ToolDenied):
        tool(guard, "mutate")(s2)


def test_a_refused_state_change_does_not_poison_later_calls(tmp_path):
    guard, _ = make_guard(tmp_path, state_cfg())
    s = guard.session("a")
    with pytest.raises(ToolDenied):
        tool(guard, "mutate", categories=["state_change", "untrusted_input"])(s)
    assert "untrusted_input" not in guard.policy.seen(s)


def test_state_change_does_not_complete_the_trifecta_by_itself(tmp_path):
    guard, _ = make_guard(tmp_path)
    s = guard.session("a")
    for name in ("read_feed", "read_db", "mutate"):
        assert tool(guard, name)(s) == "ran"


def test_bad_option_types_are_rejected_at_load_time():
    with pytest.raises(PolicyError):
        PolicyEngine({"version": "v", "strict_classification": "yes", "agents": {}})
    with pytest.raises(PolicyError):
        PolicyEngine(cfg(enforce_state_change_after_untrusted="yes"))
    with pytest.raises(PolicyError):
        PolicyEngine(cfg(state_change_allowed_tools="mutate"))


# ============================================================ 3. shared replay store

def envelope_for(tmp_path):
    sender, recipient = Signer.generate(), Signer.generate()
    registry = {"alice": sender.public_hex, "bob": recipient.public_hex}
    env = send_envelope(sender, "alice", "bob", {"hello": 1}, "trace-1", categories=["data_access"])
    return env, registry


def test_both_implementations_share_one_interface():
    assert isinstance(ReplayGuard(), ReplayStore)


def test_in_memory_guard_is_still_the_default_and_unchanged():
    g = ReplayGuard()
    assert g.seen_before("n") is False
    assert g.seen_before("n") is True


def test_sqlite_guard_remembers_across_instances(tmp_path):
    db = tmp_path / "replay.sqlite"
    assert isinstance(SqliteReplayGuard(db), ReplayStore)
    assert SqliteReplayGuard(db).seen_before("n1") is False
    assert SqliteReplayGuard(db).seen_before("n1") is True
    assert SqliteReplayGuard(db).seen_before("n2") is False


def test_sqlite_guard_forgets_nonces_after_the_ttl(tmp_path):
    now = [1000.0]
    g = SqliteReplayGuard(tmp_path / "r.sqlite", ttl_seconds=10, clock=lambda: now[0])
    assert g.seen_before("n") is False
    now[0] += 5
    assert g.seen_before("n") is True
    now[0] += 20
    assert g.seen_before("n") is False  # expired: the freshness check rejects a message this old anyway


def test_sqlite_guard_works_with_receive_envelope(tmp_path):
    env, registry = envelope_for(tmp_path)
    guard = SqliteReplayGuard(tmp_path / "r.sqlite")
    reg = KeyRegistry(registry)
    receive_envelope(env, reg, "bob", guard)
    with pytest.raises(SignatureError, match="replay"):
        receive_envelope(env, reg, "bob", guard)


def _run_worker(tmp_path, job_path):
    return subprocess.Popen([sys.executable, str(ROOT / "tests" / "_replay_worker.py"), str(job_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={**os.environ, "PYTHONPATH": str(ROOT / "src")})


def test_two_processes_replaying_one_message_second_is_refused(tmp_path):
    env, registry = envelope_for(tmp_path)
    job = tmp_path / "job.json"
    job.write_text(json.dumps({"db": str(tmp_path / "r.sqlite"), "envelope": env, "registry": registry,
                               "recipient": "bob"}), encoding="utf-8")
    outs = []
    for _ in range(2):  # strictly one after the other: separate processes, same store
        p = _run_worker(tmp_path, job)
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err
        outs.append(out.strip())
    assert outs[0] == "ACCEPTED"
    assert outs[1].startswith("REJECTED") and "replay" in outs[1]


def test_concurrent_processes_exactly_one_accepts(tmp_path):
    env, registry = envelope_for(tmp_path)
    job = tmp_path / "job.json"
    job.write_text(json.dumps({"db": str(tmp_path / "r.sqlite"), "envelope": env, "registry": registry,
                               "recipient": "bob"}), encoding="utf-8")
    procs = [_run_worker(tmp_path, job) for _ in range(6)]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, err
        results.append(out.strip())
    assert results.count("ACCEPTED") == 1, results
    assert sum(r.startswith("REJECTED") for r in results) == 5


def test_sqlite_guard_fails_closed_when_the_store_is_unusable(tmp_path):
    bad = tmp_path / "is-a-directory"
    bad.mkdir()
    with pytest.raises(Exception):
        SqliteReplayGuard(bad).seen_before("n")  # an error, never a quiet "not seen"


# ============================================================ 4. recorder channel

def test_token_with_non_ascii_characters_is_accepted_when_correct(tmp_path):
    from auditrail import RecorderService, RemoteLedger
    from auditrail.recorder import RecorderUnavailable

    ledger = Ledger(tmp_path / "l.jsonl", signer=Signer.generate(), fsync=False)
    svc = RecorderService(ledger, token="tökén-密碼", heartbeat_s=0).start()
    try:
        good = Guard(PolicyEngine(cfg()), RemoteLedger(port=svc.address[1], token="tökén-密碼"))
        assert tool(good, "read_db")(good.session("a")) == "ran"
        bad = Guard(PolicyEngine(cfg()), RemoteLedger(port=svc.address[1], token="wrong"))
        with pytest.raises(RecorderUnavailable):
            tool(bad, "read_db")(bad.session("a"))
    finally:
        svc.stop()


def test_token_is_compared_with_a_constant_time_primitive(tmp_path, monkeypatch):
    import hmac as real_hmac

    from auditrail import RecorderService, recorder

    seen = []
    original = real_hmac.compare_digest  # recorder.hmac *is* this module, so keep the real function aside

    def spy(a, b):
        seen.append((type(a), type(b)))
        return original(a, b)

    monkeypatch.setattr(recorder.hmac, "compare_digest", spy)
    svc = RecorderService(Ledger(tmp_path / "l.jsonl", fsync=False), token="s3cret", heartbeat_s=0)
    reply = svc.handle_request({"op": "call", "token": "nope", "fields": {}})
    assert reply["ok"] is False and "token" in reply["error"]
    assert seen, "token must go through hmac.compare_digest"
    assert all(t == (bytes, bytes) for t in seen), "compare fixed-length digests, not raw strings"


def test_non_string_token_is_just_wrong(tmp_path):
    from auditrail import RecorderService

    svc = RecorderService(Ledger(tmp_path / "l.jsonl", fsync=False), token="s3cret", heartbeat_s=0)
    for bad in (None, 5, ["s3cret"], {"x": 1}):
        reply = svc.handle_request({"op": "call", "token": bad, "fields": {}})
        assert reply == {"ok": False, "error": "bad or missing token"}


from auditrail import _perms  # noqa: E402


def test_posix_rules_flag_group_and_other_access_to_a_secret():
    assert _perms.posix_findings(0o600, "secret") == []
    assert _perms.posix_findings(0o400, "secret") == []
    assert _perms.posix_findings(0o640, "secret")
    assert _perms.posix_findings(0o604, "secret")
    assert _perms.posix_findings(0o666, "secret")


def test_posix_rules_flag_group_or_other_write_to_the_ledger_but_not_read():
    assert _perms.posix_findings(0o644, "writable") == []
    assert _perms.posix_findings(0o664, "writable")
    assert _perms.posix_findings(0o646, "writable")


def test_a_missing_file_is_reported_not_crashed_on(tmp_path):
    msgs = _perms.permission_warnings(tmp_path / "nope.key", "secret")
    assert msgs and "does not exist" in msgs[0]


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_posix_check_on_a_real_file(tmp_path):
    p = tmp_path / "k.key"
    p.write_text("x")
    p.chmod(0o600)
    assert _perms.permission_warnings(p, "secret") == []
    p.chmod(0o644)
    assert _perms.permission_warnings(p, "secret")


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_windows_check_flags_a_secret_readable_by_everyone(tmp_path):
    p = tmp_path / "k.key"
    p.write_text("x")
    me = os.environ["USERNAME"]
    subprocess.run(["icacls", str(p), "/inheritance:r", "/grant:r", f"{me}:(F)"], check=True, capture_output=True)
    assert _perms.permission_warnings(p, "secret") == []
    subprocess.run(["icacls", str(p), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)  # Everyone
    msgs = _perms.permission_warnings(p, "secret")
    assert msgs and "Everyone" in msgs[0]


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_windows_check_flags_an_inherited_users_group_grant(tmp_path):
    p = tmp_path / "k.key"
    p.write_text("x")
    subprocess.run(["icacls", str(p), "/grant", "*S-1-5-32-545:(R)"], check=True, capture_output=True)  # BUILTIN\Users
    msgs = _perms.permission_warnings(p, "secret")
    assert msgs and any("Users" in m for m in msgs)


def test_recorder_startup_prints_a_warning_for_a_loose_key(tmp_path, capsys):
    from auditrail.recorder import startup_permission_warnings

    key = tmp_path / "r.key"
    key.write_text("00" * 32)
    if os.name == "nt":
        subprocess.run(["icacls", str(key), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    else:
        key.chmod(0o644)
    msgs = startup_permission_warnings(key_path=key, ledger_path=tmp_path / "l.jsonl", anchors_path=None)
    assert any("key" in m.lower() for m in msgs)
