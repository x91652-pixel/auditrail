"""Policy engine: allow-listing plus "lethal trifecta" enforcement.

The lethal trifecta (coined by Simon Willison, and cited by OWASP's Top 10
for Agentic Applications 2026 as the pattern behind most real-world agent
data-exfiltration incidents) is: an agent session that simultaneously has
(1) access to private/sensitive data, (2) exposure to untrusted, attacker-
influenceable content, and (3) a way to communicate externally. Any two of
those are usually fine; all three in the same session is how a prompt
injected into "untrusted content" turns into a real exfiltration path
(EchoLeak, Slack AI, ForcedLeak, GitHub MCP all follow this shape).

This engine tracks, per session, which categories have been touched so
far, and refuses to allow a tool call that would complete the trifecta --
unless the policy explicitly marks that tool as trifecta-exempt (meaning a
human already reviewed and accepted the risk for that specific action).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared dependency
    yaml = None

TRIFECTA = {"data_access", "untrusted_input", "external_comm"}


@dataclass
class Decision:
    allow: bool
    reason: Optional[str] = None


@dataclass
class SessionState:
    session_id: str
    agent_id: str
    categories_seen: set = field(default_factory=set)


class PolicyError(ValueError):
    pass


class PolicyEngine:
    def __init__(self, config: dict):
        if "version" not in config:
            raise PolicyError("policy is missing required 'version' field")
        self.version: str = config["version"]
        self.agents: dict = config.get("agents", {})
        self.default: dict = config.get(
            "default", {"allowed_tools": [], "enforce_lethal_trifecta": True}
        )

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        if yaml is None:
            raise RuntimeError("pyyaml is required to load policy files: pip install pyyaml")
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls(data)

    def _agent_config(self, agent_id: str) -> dict:
        return self.agents.get(agent_id, self.default)

    def categories_for(self, agent_id: str, tool: str) -> list[str]:
        cfg = self._agent_config(agent_id)
        return list(cfg.get("tool_categories", {}).get(tool, []))

    def check(self, session: SessionState, tool: str, extra_categories: Optional[list[str]] = None) -> Decision:
        cfg = self._agent_config(session.agent_id)
        allowed_tools = set(cfg.get("allowed_tools", []))
        if tool not in allowed_tools:
            return Decision(allow=False, reason=f"tool '{tool}' is not allow-listed for agent '{session.agent_id}'")

        categories = set(cfg.get("tool_categories", {}).get(tool, []))
        if extra_categories:
            categories |= set(extra_categories)

        enforce = cfg.get("enforce_lethal_trifecta", True)
        exempt = set(cfg.get("trifecta_exempt_tools", []))
        would_see = session.categories_seen | categories
        if enforce and tool not in exempt and TRIFECTA.issubset(would_see):
            already = session.categories_seen & TRIFECTA
            adding = categories & TRIFECTA
            return Decision(
                allow=False,
                reason=(
                    "lethal_trifecta: session already touched "
                    f"{sorted(already) or '{}'}, tool '{tool}' would add {sorted(adding)}, "
                    "completing data_access + untrusted_input + external_comm in one session"
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
