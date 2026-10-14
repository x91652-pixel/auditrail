"""guarded_tool: wrap a real tool function with policy + ledger + isolation.

This is the integration point: you keep your real tool functions exactly
as they are (a function that reads a file, calls an API, writes to a
database, invokes another agent) and wrap them with `guarded_tool`. Nothing
about the tool's own logic is mocked or replaced -- guarded_tool only
decides, before each call, whether the policy engine allows it, and
records what happened afterwards.

Guard also writes the other evidence the verifier needs:
  * heartbeats (heartbeat() / start_heartbeats()): the wrapped tool list, the
    policy hash, and how many calls were intercepted vs. recorded, so a silent
    period or a call that ran without evidence becomes visible;
  * both sides of agent-to-agent messages (send_message / receive_message /
    accept_receipt), with the sender's trifecta categories inherited by the
    receiver's workflow.

Isolation note (read this before trusting it): `isolate=True` runs the
wrapped call in a separate OS subprocess (`python -m
auditrail._isolate_worker`) with an allow-listed environment -- only a
handful of OS variables (PATH, TEMP, locale...) plus anything you name in
env_passthrough reach the tool, so ambient API keys are not inherited --
and a wall-clock timeout. That stops a runaway or hung tool call and
prevents accidental use of the parent process's environment variables. It
is NOT a security sandbox against a determined attacker -- it shares the
filesystem (including ~/.aws, ~/.ssh and any credential files), network,
and OS with the parent. A real adversarial boundary needs a container or
microVM (gVisor, Firecracker, Docker with dropped capabilities). Treat
`isolate=True` as "blast radius reduction for bugs," not as a containment
guarantee for hostile code. That gap is tracked in ROADMAP.md.

Because the call crosses a process boundary, the wrapped function must be
importable by `module + top-level name` (defined at module scope, not a
closure/lambda/method; a function in a script run directly also works) and
its arguments and return value must be JSON-serializable.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import subprocess
import sys as _sys
import threading
import time
from typing import Any, Callable, Iterable, Optional

RESULT_MARKER = "@@auditrail-result@@"  # must match _isolate_worker.RESULT_MARKER (not imported: see runpy)
from .ledger import Ledger
from .policy import Decision, PolicyEngine, SessionState

# Variables a Python subprocess needs to start and behave normally. Nothing else
# is inherited unless named in env_passthrough.
SAFE_ENV = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
    "HOME", "USERPROFILE", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ",
)


class ToolDenied(PermissionError):
    def __init__(self, tool: str, reason: str):
        super().__init__(f"auditrail denied call to '{tool}': {reason}")
        self.tool = tool
        self.reason = reason


def _require_isolatable(fn: Callable) -> None:
    qualname = getattr(fn, "__qualname__", fn.__name__)
    if "<locals>" in qualname or "." in qualname:
        raise TypeError(
            f"guarded_tool(..., isolate=True) requires '{fn.__name__}' to be defined at "
            f"module top level in '{fn.__module__}' (found qualname '{qualname}'). The "
            "sandbox subprocess imports it as `module.name`, which only works for "
            "plain module-level functions. Move it out of any enclosing "
            "function/class, or set isolate=False."
        )
    if fn.__module__ == "__main__" and not getattr(_sys.modules.get("__main__"), "__file__", None):
        raise TypeError(
            f"guarded_tool(..., isolate=True) cannot isolate '{fn.__name__}': it is defined in an "
            "interactive session with no source file. Put it in a module or script file."
        )


def _isolated_env(passthrough: Iterable[str]) -> dict:
    names = set(SAFE_ENV) | set(passthrough)
    env = {k: v for k, v in os.environ.items() if k.upper() in names or k in names}
    env["PYTHONIOENCODING"] = "utf-8"
    sys_path_str = os.pathsep.join(p for p in _sys.path if p)
    existing_pp = os.environ.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(x for x in (sys_path_str, existing_pp) if x)
    return env


def _call_isolated(fn: Callable, args: tuple, kwargs: dict, timeout: float, env_passthrough: Iterable[str] = ()) -> Any:
    job = {"module": fn.__module__, "qualname": fn.__name__, "args": list(args), "kwargs": kwargs}
    if fn.__module__ == "__main__":
        job["path"] = os.path.abspath(_sys.modules["__main__"].__file__)
    try:
        payload = json.dumps(job)
    except TypeError as exc:
        raise TypeError(
            f"guarded_tool(..., isolate=True) requires JSON-serializable arguments for "
            f"'{fn.__name__}': {exc}"
        ) from exc

    try:
        proc = subprocess.run(
            [_sys.executable, "-m", "auditrail._isolate_worker"],
            input=payload, capture_output=True, text=True, encoding="utf-8", timeout=timeout,
            env=_isolated_env(env_passthrough),
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"sandboxed call to {fn.__name__!r} exceeded {timeout}s") from exc

    # split on "\n" only: str.splitlines() would also split inside tool output on \x1c-\x1e etc.
    marked = [ln.rstrip("\r")[len(RESULT_MARKER):] for ln in (proc.stdout or "").split("\n") if ln.startswith(RESULT_MARKER)]
    if proc.returncode != 0 or not marked:
        raise RuntimeError(f"sandboxed call to {fn.__name__!r} failed (exit {proc.returncode}): {(proc.stderr or '').strip()}")

    outcome = json.loads(marked[-1])
    if outcome["status"] == "error":
        raise RuntimeError(f"sandboxed call to {fn.__name__!r} raised: {outcome['error']}")
    return outcome["result"]


class Guard:
    """Binds a PolicyEngine + Ledger together so tools can be decorated.

    ledger: a Ledger, or a recorder.RemoteLedger so that the signing key and the
    ledger file live in a process the agent cannot touch.
    record_error_text: by default a failed call's reason is recorded as the
    exception type plus a digest of its message, because exception messages often
    echo raw arguments. Set True when you need the text for forensics and accept
    that it may contain sensitive data.
    """

    def __init__(
        self,
        policy: PolicyEngine,
        ledger: Ledger,
        record_error_text: bool = False,
        recorder_id: Optional[str] = None,
    ):
        self.policy = policy
        self.ledger = ledger
        self.record_error_text = record_error_text
        self.recorder_id = recorder_id or f"guard-{os.getpid()}"
        self.tools: set[str] = set()
        self._count_lock = threading.Lock()
        self._attempted = 0
        self._recorded = 0
        self._hb_stop: Optional[threading.Event] = None

    # ------------------------------------------------------------ sessions
    def session(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        inherited: Iterable[str] = (),
    ) -> SessionState:
        """A new session. Pass trace_id to join an existing workflow (shared trifecta state)."""
        sid = session_id or self.ledger.new_session_id()
        s = SessionState(session_id=sid, agent_id=agent_id, trace_id=trace_id or sid)
        if inherited:
            self.policy.inherit(s, inherited)
        return s

    # ------------------------------------------------------------ evidence
    def _write(self, **fields: Any) -> None:
        self.ledger.record(**fields)
        with self._count_lock:
            self._recorded += 1

    def _reason_for(self, exc: Exception) -> str:
        if self.record_error_text:
            return f"{type(exc).__name__}: {exc}"
        digest = hashlib.sha256(str(exc).encode("utf-8")).hexdigest()
        return f"{type(exc).__name__} (message sha256:{digest[:16]})"

    def heartbeat(self, interval_s: int = 60) -> None:
        """Write one heartbeat: tools wrapped so far, policy hash, intercepted vs. recorded calls."""
        with self._count_lock:
            attempted, recorded = self._attempted, self._recorded
            self._attempted = self._recorded = 0
        self.ledger.record_heartbeat(
            recorder_id=self.recorder_id, tools=sorted(self.tools), policy_version=self.policy.version,
            policy_hash=self.policy.policy_hash, calls_attempted=attempted, calls_recorded=recorded,
            interval_s=int(interval_s),
        )

    def start_heartbeats(self, interval_s: int = 60) -> None:
        """Write a heartbeat now and every interval_s seconds from a daemon thread."""
        if self._hb_stop is not None:
            return
        self._hb_stop = threading.Event()
        stop = self._hb_stop

        def loop() -> None:
            while True:
                try:
                    self.heartbeat(interval_s)
                except Exception:  # noqa: BLE001 - a missed beat shows up as a gap; never kill the agent
                    pass
                if stop.wait(interval_s):
                    return

        threading.Thread(target=loop, name="auditrail-heartbeat", daemon=True).start()

    def stop_heartbeats(self, final: bool = True) -> None:
        if self._hb_stop is not None:
            self._hb_stop.set()
            self._hb_stop = None
        if final:
            self.heartbeat()

    # ------------------------------------------------------------ agent-to-agent
    def send_message(self, session: SessionState, identity, recipient: str, payload: Any) -> dict:
        """Sign an envelope from session.agent_id to recipient and record the send.

        The envelope carries this workflow's categories, so the receiver's policy
        counts them (a split trifecta across agents is still a trifecta).
        """
        from .agent_bridge import message_digest, send_envelope

        env = send_envelope(identity, session.agent_id, recipient, payload, session.trace_id,
                            categories=self.policy.seen(session))
        self.ledger.record_event(
            "a2a_send", agent_id=session.agent_id, session_id=session.session_id, trace_id=session.trace_id,
            peer=recipient, msg_id=env["msg_id"], msg_digest=message_digest(env), categories=env["categories"],
        )
        return env

    def receive_message(self, envelope: dict, registry, agent_id: str, identity, replay_guard,
                        max_age_seconds: float = 60.0) -> tuple[SessionState, Any, dict]:
        """Verify an envelope for agent_id, record it, and return (session, payload, receipt).

        The returned session joins the sender's workflow (trace_id) and inherits
        its categories. A rejected message is recorded too, then SignatureError is raised.
        """
        from .agent_bridge import SignatureError, make_receipt, receive_envelope

        try:
            d = receive_envelope(envelope, registry, agent_id, replay_guard, max_age_seconds)
        except SignatureError as exc:
            self.ledger.record_event(
                "a2a_recv", agent_id=agent_id, status="rejected", reason=str(exc),
                peer=str(envelope.get("sender")) if isinstance(envelope, dict) else None,
                msg_id=str(envelope.get("msg_id")) if isinstance(envelope, dict) else None,
            )
            raise
        session = self.session(agent_id, trace_id=d.trace_id, inherited=d.categories)
        receipt = make_receipt(identity, d)
        self.ledger.record_event(
            "a2a_recv", agent_id=agent_id, status="accepted", session_id=session.session_id, trace_id=d.trace_id,
            peer=d.sender, msg_id=d.msg_id, msg_digest=d.msg_digest, categories=sorted(d.categories),
            sender_sig=d.sender_sig, receipt_sig=receipt["sig"],
        )
        return session, d.payload, receipt

    def accept_receipt(self, session: SessionState, envelope: dict, receipt: dict, registry) -> None:
        """Verify the recipient's receipt for a message this side sent, and record it."""
        from .agent_bridge import message_digest, verify_receipt

        digest = message_digest(envelope)
        verify_receipt(receipt, registry, digest, envelope["recipient"])
        self.ledger.record_event(
            "a2a_ack", agent_id=session.agent_id, session_id=session.session_id, trace_id=session.trace_id,
            peer=envelope["recipient"], msg_id=envelope["msg_id"], msg_digest=digest, receipt_sig=receipt["sig"],
        )

    # ------------------------------------------------------------ tools
    def guarded_tool(
        self,
        name: str,
        categories: Iterable[str] = (),
        isolate: bool = False,
        timeout: float = 10.0,
        on_deny: str = "raise",
        env_passthrough: Iterable[str] = (),
    ):
        """Decorator. The wrapped function's first argument must be a SessionState.

        on_deny: "raise" (default) raises ToolDenied, or "return_none" to
        return None instead -- useful when the caller is an LLM tool-use
        loop that should see a structured refusal rather than a stack trace.
        env_passthrough: extra environment variable names an isolated tool may see.
        """
        categories = list(categories)
        env_passthrough = tuple(env_passthrough)
        self.tools.add(name)

        def deco(fn: Callable) -> Callable:
            if isolate:
                _require_isolatable(fn)

            @functools.wraps(fn)
            def wrapper(session: SessionState, *args: Any, **kwargs: Any) -> Any:
                with self._count_lock:
                    self._attempted += 1
                decision: Decision = self.policy.check(session, name, extra_categories=categories)
                call_args = {"args": args, "kwargs": kwargs}
                common = dict(agent_id=session.agent_id, session_id=session.session_id, trace_id=session.trace_id,
                              policy_version=self.policy.version, policy_hash=self.policy.policy_hash,
                              tool=name, categories=categories, args=call_args)

                if not decision.allow:
                    self._write(**common, decision="deny", reason=decision.reason)
                    if on_deny == "return_none":
                        return None
                    raise ToolDenied(name, decision.reason or "denied")

                start = time.monotonic()
                try:
                    if isolate:
                        result = _call_isolated(fn, args, kwargs, timeout, env_passthrough)
                        effective_decision = "sandboxed"
                    else:
                        result = fn(*args, **kwargs)
                        effective_decision = "allow"
                except Exception as exc:
                    # A failed call may still have touched data before failing,
                    # so it counts toward the workflow's trifecta state (conservative).
                    self.policy.commit(session, name, extra_categories=categories)
                    self._write(**common, decision="error", reason=self._reason_for(exc),
                                duration_ms=(time.monotonic() - start) * 1000)
                    raise
                duration_ms = (time.monotonic() - start) * 1000

                self.policy.commit(session, name, extra_categories=categories)
                self._write(**common, decision=effective_decision, result=result, duration_ms=duration_ms)
                return result

            wrapper.__auditrail_tool__ = name
            return wrapper

        return deco
