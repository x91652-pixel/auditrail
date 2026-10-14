"""Policy engine: allow-listing plus "lethal trifecta" enforcement.

The lethal trifecta (coined by Simon Willison, and cited by OWASP's Top 10
for Agentic Applications 2026 as the pattern behind most real-world agent
data-exfiltration incidents) is: an agent session that simultaneously has
(1) access to private/sensitive data, (2) exposure to untrusted, attacker-
influenceable content, and (3) a way to communicate externally. Any two of
those are usually fine; all three in the same session is how a prompt
injected into "untrusted content" turns into a real exfiltration path
(EchoLeak, Slack AI, ForcedLeak, GitHub MCP all follow this shape).

This engine tracks which categories have been touched so far and refuses to
allow a tool call that would complete the trifecta -- unless the policy
explicitly marks that tool as trifecta-exempt (meaning a human already
reviewed and accepted the risk for that specific action).

Scope of the tracking is a *workflow* (trace_id), not just a session. Sessions
that share a trace_id share their categories, and a message from another agent
carries its sender's categories along (agent_bridge.Envelope.categories), so
"agent A reads private data, hands it to B, B reads a web page and emails out"
is caught even though no single session held all three. A session that is not
linked to any other (its own trace_id) behaves exactly as in v0.1.

Two options tighten the defaults without changing them for existing policies:

* ``strict`` (``PolicyEngine(config, strict=True)`` or ``strict_classification: true``
  in the policy): a wrapped tool whose categories are empty -- nothing declared in
  the policy and nothing at the call site -- is refused and the refusal recorded as
  ``unclassified_tool``. A tool that really touches none of the risk categories must
  say so with an explicit label such as ``internal``; an empty list is not a label.
* ``enforce_state_change_after_untrusted`` (per agent): a tool labelled
  ``state_change`` -- it changes an external system without necessarily
  communicating outward (a refund, a reroute) -- is refused once the workflow has
  touched ``untrusted_input``, unless the tool is listed in
  ``state_change_allowed_tools``.

Neither can know whether a label is *true*. They make a missing label a refusal and
give write actions a rule to be subject to; see SECURITY.md for what remains.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared dependency
    yaml = None

TRIFECTA = {"data_access", "untrusted_input", "external_comm"}
STATE_CHANGE = "state_change"
UNTRUSTED = "untrusted_input"
INTERNAL = "internal"  # "touches none of the risk categories"; exclusive of every other label


def label_conflict(tool: str, categories) -> Optional[str]:
    """Why `categories` is contradictory for `tool`, or None.

    `internal` is the explicit statement that a tool touches no risk category, so
    pairing it with any other label is a contradiction -- left alone it would be a way
    to dodge the state_change and trifecta rules while looking classified.
    """
    cats = set(categories or ())
    others = sorted(cats - {INTERNAL})
    if INTERNAL in cats and others:
        return (f"tool '{tool}' is labelled 'internal' and also {others}: 'internal' means it touches none of the "
                "risk categories, so it cannot carry another label. Remove one of them.")
    return None


class UnclassifiedToolWarning(UserWarning):
    """A tool was wrapped without any category while the policy is not in strict mode."""


@dataclass
class Decision:
    allow: bool
    reason: Optional[str] = None


@dataclass
class SessionState:
    session_id: str
    agent_id: str
    categories_seen: set = field(default_factory=set)
    trace_id: str = ""  # the workflow this session belongs to; defaults to its own session_id

    def __post_init__(self) -> None:
        if not self.trace_id:
            self.trace_id = self.session_id


class PolicyError(ValueError):
    pass


class PolicyEngine:
    def __init__(self, config: dict, strict: Optional[bool] = None):
        if "version" not in config:
            raise PolicyError("policy is missing required 'version' field")
        self._validate_options(config)
        self._validate_labels(config)
        from_config = bool(config.get("strict_classification", False))
        #: whether a tool with no declared category is refused (see module docstring)
        self.strict: bool = from_config if strict is None else bool(strict)
        if self.strict != from_config:
            config = {**config, "strict_classification": self.strict}  # so the hash says which mode ran
        self.version: str = config["version"]
        self.agents: dict = config.get("agents", {})
        self.default: dict = config.get(
            "default", {"allowed_tools": [], "enforce_lethal_trifecta": True}
        )
        # sha256 of the whole policy, so evidence can say exactly which rules were in force
        self.policy_hash: str = hashlib.sha256(
            json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()
        self._workflows: dict[str, set] = {}

    @classmethod
    def from_yaml(cls, path: str, strict: Optional[bool] = None) -> "PolicyEngine":
        if yaml is None:
            raise RuntimeError("pyyaml is required to load policy files: pip install pyyaml")
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls(data, strict=strict)

    @staticmethod
    def _validate_options(config: dict) -> None:
        if not isinstance(config.get("strict_classification", False), bool):
            raise PolicyError("'strict_classification' must be true or false")
        sections = [config.get("default") or {}, *(config.get("agents") or {}).values()]
        for cfg in sections:
            if not isinstance(cfg.get("enforce_state_change_after_untrusted", False), bool):
                raise PolicyError("'enforce_state_change_after_untrusted' must be true or false")
            allowed = cfg.get("state_change_allowed_tools", [])
            if not isinstance(allowed, list) or not all(isinstance(t, str) for t in allowed):
                raise PolicyError("'state_change_allowed_tools' must be a list of tool names")

    @staticmethod
    def _sections(config: dict) -> list:
        return [("default", config.get("default") or {}),
                *((f"agent '{name}'", cfg or {}) for name, cfg in (config.get("agents") or {}).items())]

    @classmethod
    def _validate_labels(cls, config: dict) -> None:
        for where, cfg in cls._sections(config):
            for tool, cats in (cfg.get("tool_categories") or {}).items():
                if isinstance(cats, list):
                    why = label_conflict(tool, cats)
                    if why:
                        raise PolicyError(f"{why} (in {where})")

    def check_call_site_labels(self, tool: str, categories) -> None:
        """Raise PolicyError if the labels given where the tool is wrapped contradict themselves
        or contradict what the policy says about the same tool."""
        why = label_conflict(tool, categories)
        if why:
            raise PolicyError(f"{why} (at the call site)")
        mine = set(categories or ())
        for where, cfg in self._sections({"default": self.default, "agents": self.agents}):
            theirs = set((cfg.get("tool_categories") or {}).get(tool) or ())
            why = label_conflict(tool, mine | theirs)
            if why:
                raise PolicyError(f"{why} (call site says {sorted(mine)}, {where} says {sorted(theirs)})")

    def classified_by_policy(self, tool: str) -> bool:
        """True if any agent (or the default) gives `tool` at least one category in the policy."""
        sections = [self.default, *self.agents.values()]
        return any(cfg.get("tool_categories", {}).get(tool) for cfg in sections)

    def _agent_config(self, agent_id: str) -> dict:
        return self.agents.get(agent_id, self.default)

    def categories_for(self, agent_id: str, tool: str) -> list[str]:
        cfg = self._agent_config(agent_id)
        return list(cfg.get("tool_categories", {}).get(tool, []))

    # ------------------------------------------------------------ workflows
    def workflow_categories(self, trace_id: str) -> set:
        return set(self._workflows.get(trace_id, set()))

    def inherit(self, session: SessionState, categories: Iterable[str]) -> None:
        """Add categories that arrived from elsewhere (another agent's message) to this session's workflow."""
        self._workflows.setdefault(session.trace_id, set()).update(categories)

    def end_workflow(self, trace_id: str) -> None:
        """Forget a finished workflow's categories (they otherwise live as long as the engine)."""
        self._workflows.pop(trace_id, None)

    def seen(self, session: SessionState) -> set:
        return set(session.categories_seen) | self._workflows.get(session.trace_id, set())

    def check(self, session: SessionState, tool: str, extra_categories: Optional[list[str]] = None) -> Decision:
        cfg = self._agent_config(session.agent_id)
        allowed_tools = set(cfg.get("allowed_tools", []))
        if tool not in allowed_tools:
            return Decision(allow=False, reason=f"tool '{tool}' is not allow-listed for agent '{session.agent_id}'")

        categories = set(cfg.get("tool_categories", {}).get(tool, []))
        if extra_categories:
            categories |= set(extra_categories)

        why = label_conflict(tool, categories)
        if why:
            return Decision(allow=False, reason=f"label_conflict: {why}")

        if self.strict and not categories:
            return Decision(
                allow=False,
                reason=(
                    f"unclassified_tool: tool '{tool}' has no category in the policy or at the call site "
                    "(strict mode refuses it; label it, e.g. 'internal' if it touches none of the risk categories)"
                ),
            )

        enforce = cfg.get("enforce_lethal_trifecta", True)
        exempt = set(cfg.get("trifecta_exempt_tools", []))
        seen = self.seen(session)
        would_see = seen | categories
        if enforce and tool not in exempt and TRIFECTA.issubset(would_see):
            already = seen & TRIFECTA
            adding = categories & TRIFECTA
            inherited = (seen - session.categories_seen) & TRIFECTA
            scope = "one session" if not inherited else f"one workflow (trace {session.trace_id}; inherited {sorted(inherited)})"
            return Decision(
                allow=False,
                reason=(
                    "lethal_trifecta: session already touched "
                    f"{sorted(already) or '{}'}, tool '{tool}' would add {sorted(adding)}, "
                    f"completing data_access + untrusted_input + external_comm in {scope}"
                ),
            )
        if (
            cfg.get("enforce_state_change_after_untrusted", False)
            and STATE_CHANGE in categories
            and UNTRUSTED in would_see
            and tool not in set(cfg.get("state_change_allowed_tools", []))
        ):
            return Decision(
                allow=False,
                reason=(
                    f"state_change_after_untrusted: tool '{tool}' changes external state and this workflow has "
                    "touched untrusted_input; list it in state_change_allowed_tools if that is intended"
                ),
            )
        return Decision(allow=True)

    def commit(self, session: SessionState, tool: str, extra_categories: Optional[list[str]] = None) -> None:
        """Record that `tool`'s categories are now part of this session's history.

        Call this only after an allowed call actually executes -- a denied
        call must not count towards future trifecta checks.
        """
        cats = set(self.categories_for(session.agent_id, tool))
        if extra_categories:
            cats |= set(extra_categories)
        session.categories_seen |= cats
        if session.trace_id != session.session_id or session.trace_id in self._workflows:
            # only shared workflows need engine-side state; a lone session's set lives on the session
            self._workflows.setdefault(session.trace_id, set()).update(cats)
