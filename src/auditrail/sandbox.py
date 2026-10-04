"""guarded_tool: wrap a real tool function with policy + ledger + isolation.

This is the integration point: you keep your real tool functions exactly
as they are (a function that reads a file, calls an API, writes to a
database, invokes another agent) and wrap them with `guarded_tool`. Nothing
about the tool's own logic is mocked or replaced -- guarded_tool only
decides, before each call, whether the policy engine allows it, and
records what happened afterwards.

Isolation note (read this before trusting it): `isolate=True` runs the
wrapped call in a separate OS subprocess (`python -m
auditrail._isolate_worker`) with a stripped environment -- ambient
secrets like API keys are not inherited unless you explicitly pass them
through -- and a wall-clock timeout. That stops a runaway or hung tool
call and prevents accidental use of the parent process's environment
variables. It is NOT a security sandbox against a determined attacker --
it shares the filesystem, network, and OS with the parent. A real
adversarial boundary needs a container or microVM (gVisor, Firecracker,
Docker with dropped capabilities). Treat `isolate=True` as "blast radius
reduction for bugs," not as a containment guarantee for hostile code.
That gap is tracked in ROADMAP.md.

Because the call crosses a process boundary, the wrapped function must be
importable by `module + top-level name` (i.e. defined at module scope,
not a closure/lambda/method) and its arguments and return value must be
JSON-serializable -- the same constraint real agent tool-calling APIs
already impose on tool inputs/outputs, so in practice this is rarely a
real limitation.
"""
from __future__ import annotations

import functools
import json
import os
import subprocess
import sys as _sys
import time
from typing import Any, Callable, Iterable, Optional

from .ledger import Ledger
from .policy import Decision, PolicyEngine, SessionState


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


def _call_isolated(fn: Callable, args: tuple, kwargs: dict, timeout: float) -> Any:
    try:
        payload = json.dumps({"module": fn.__module__, "qualname": fn.__name__, "args": list(args), "kwargs": kwargs})
    except TypeError as exc:
        raise TypeError(
            f"guarded_tool(..., isolate=True) requires JSON-serializable arguments for "
            f"'{fn.__name__}': {exc}"
        ) from exc

    env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD"))}
    env["PYTHONIOENCODING"] = "utf-8"
    sys_path_str = os.pathsep.join(p for p in _sys.path if p)
    existing_pp = os.environ.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(x for x in (sys_path_str, existing_pp) if x)

    try:
        proc = subprocess.run(
            [_sys.executable, "-m", "auditrail._isolate_worker"],
            input=payload, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"sandboxed call to {fn.__name__!r} exceeded {timeout}s") from exc

    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"sandboxed call to {fn.__name__!r} failed (exit {proc.returncode}): {proc.stderr.strip()}")

    outcome = json.loads(proc.stdout)
    if outcome["status"] == "error":
        raise RuntimeError(f"sandboxed call to {fn.__name__!r} raised: {outcome['error']}")
    return outcome["result"]


class Guard:
    """Binds a PolicyEngine + Ledger together so tools can be decorated."""

    def __init__(self, policy: PolicyEngine, ledger: Ledger):
        self.policy = policy
        self.ledger = ledger

    def session(self, agent_id: str, session_id: Optional[str] = None) -> SessionState:
        return SessionState(session_id=session_id or self.ledger.new_session_id(), agent_id=agent_id)

    def guarded_tool(
        self,
        name: str,
        categories: Iterable[str] = (),
        isolate: bool = False,
        timeout: float = 10.0,
        on_deny: str = "raise",
    ):
        """Decorator. The wrapped function's first argument must be a SessionState.

        on_deny: "raise" (default) raises ToolDenied, or "return_none" to
        return None instead -- useful when the caller is an LLM tool-use
        loop that should see a structured refusal rather than a stack trace.
        """
        categories = list(categories)

        def deco(fn: Callable) -> Callable:
            if isolate:
                _require_isolatable(fn)

            @functools.wraps(fn)
            def wrapper(session: SessionState, *args: Any, **kwargs: Any) -> Any:
                decision: Decision = self.policy.check(session, name, extra_categories=categories)
                call_args = {"args": args, "kwargs": kwargs}

                if not decision.allow:
                    self.ledger.record(
                        agent_id=session.agent_id,
                        session_id=session.session_id,
                        policy_version=self.policy.version,
                        tool=name,
                        categories=categories,
                        args=call_args,
                        decision="deny",
                        reason=decision.reason,
                    )
                    if on_deny == "return_none":
                        return None
                    raise ToolDenied(name, decision.reason or "denied")

                start = time.monotonic()
                try:
                    if isolate:
                        result = _call_isolated(fn, args, kwargs, timeout)
                        effective_decision = "sandboxed"
                    else:
                        result = fn(*args, **kwargs)
                        effective_decision = "allow"
                except Exception as exc:
                    # A failed call may still have touched data before failing,
                    # so it counts toward the session's trifecta state (conservative).
                    self.policy.commit(session, name, extra_categories=categories)
                    self.ledger.record(
                        agent_id=session.agent_id,
                        session_id=session.session_id,
                        policy_version=self.policy.version,
                        tool=name,
                        categories=categories,
                        args=call_args,
                        decision="error",
                        reason=f"{type(exc).__name__}: {exc}",
                        duration_ms=(time.monotonic() - start) * 1000,
                    )
                    raise
                duration_ms = (time.monotonic() - start) * 1000

                self.policy.commit(session, name, extra_categories=categories)
                self.ledger.record(
                    agent_id=session.agent_id,
                    session_id=session.session_id,
                    policy_version=self.policy.version,
                    tool=name,
                    categories=categories,
                    args=call_args,
                    decision=effective_decision,
                    result=result,
                    duration_ms=duration_ms,
                )
                return result

            wrapper.__auditrail_tool__ = name
            return wrapper

        return deco
