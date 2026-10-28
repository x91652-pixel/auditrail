"""Policy engine: allow-listing plus "lethal trifecta" enforcement.

The lethal trifecta (named by Simon Willison, June 2025) is: an agent session
that simultaneously has (1) access to private/sensitive data, (2) exposure to
untrusted, attacker-influenceable content, and (3) a way to communicate
externally. With all three in the same session, a prompt injected into
"untrusted content" can become an exfiltration path.

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

import difflib
import hashlib
import json
import re
import threading
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
AGENT_TO_AGENT = "agent_to_agent"  # documented in policies/example_policy.yaml; no engine rule depends on it
#: Every category name the engine knows without a declaration. Anything else must be declared under the
#: policy's top-level `custom_categories`, so a typo or a different spelling is an error, not a new category.
BUILTIN_CATEGORIES = frozenset(TRIFECTA | {STATE_CHANGE, INTERNAL, AGENT_TO_AGENT})
_CANONICAL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")  # always used with fullmatch: `$` would accept a trailing newline


def suggest_category(name: str, known) -> Optional[str]:
    """The known name `name` was most likely meant to be: the same name once case, surrounding
    whitespace and '-'/space separators are normalised, else the closest by edit similarity."""
    if not isinstance(name, str):
        return None
    normalised = re.sub(r"[\s\-]+", "_", name.strip().lower())
    if normalised in known:
        return normalised
    close = difflib.get_close_matches(normalised, sorted(known), n=1, cutoff=0.75)
    return close[0] if close else None


def unknown_category_message(name: str, known, subject: str) -> str:
    hint = suggest_category(name, known)
    text = f"unknown category {name!r} for {subject}"
    text += f"; did you mean {hint!r}?" if hint else "."
    return (f"{text} Known: {sorted(known)}. A category of your own must be declared once, in the policy's "
            "top-level 'custom_categories' list, in the form lower_snake_case.")


def string_list(value, what: str) -> list:
    """`value` as a list of strings, or PolicyError(what ...).

    Anything else is refused rather than coerced: set("state_change") would quietly become a set of
    characters, and None or a number would only fail later, at call time, inside the engine.
    """
    if not isinstance(value, (list, tuple)):
        raise PolicyError(f"{what} must be a list of strings, got {type(value).__name__} {value!r}")
    for item in value:
        if not isinstance(item, str):
            raise PolicyError(f"{what} must be a list of strings, found {type(item).__name__} {item!r} in {list(value)!r}")
    return list(value)


def call_site_list(value, what: str) -> list:
    """Like string_list for labels given in Python code: any iterable of strings, but never a bare string
    (list("state_change") would be eleven one-letter categories)."""
    if isinstance(value, (str, bytes, dict)) or not hasattr(value, "__iter__"):
        raise PolicyError(f"{what} must be a list of strings, got {type(value).__name__} {value!r}")
    return string_list(list(value), what)


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


#: Most nodes a policy file may expand to once YAML aliases are resolved. A real policy is a few hundred;
#: a "billion laughs" file is a few hundred bytes that expands to millions, so it is refused before it is built.
MAX_POLICY_NODES = 100_000


def load_policy_yaml(text: str):
    """Parse policy YAML (safe loader), refusing alias expansion beyond MAX_POLICY_NODES nodes.

    The node graph is composed first and its expanded size counted without expanding it, so a file that
    would blow up is refused in linear time and memory, before anything is built or hashed."""
    if yaml is None:
        raise RuntimeError("pyyaml is required to load policy files: pip install pyyaml")
    loader = yaml.SafeLoader(text)
    try:
        root = loader.get_single_node()
        if root is None:
            return None
        sizes: dict = {}
        active: set = set()

        def size(node) -> int:
            key = id(node)
            if key in sizes:
                return sizes[key]
            if key in active:
                raise PolicyError("policy YAML contains a recursive alias")
            active.add(key)
            total = 1
            if isinstance(node, yaml.SequenceNode):
                for child in node.value:
                    total += size(child)
                    if total > MAX_POLICY_NODES:
                        break
            elif isinstance(node, yaml.MappingNode):
                for k, v in node.value:
                    total += size(k) + size(v)
                    if total > MAX_POLICY_NODES:
                        break
            active.discard(key)
            total = min(total, MAX_POLICY_NODES + 1)
            sizes[key] = total
            return total

        try:
            n = size(root)
        except RecursionError:
            raise PolicyError("policy YAML is nested too deeply") from None
        if n > MAX_POLICY_NODES:
            raise PolicyError(f"policy YAML expands to more than {MAX_POLICY_NODES} nodes once aliases are "
                              "resolved; remove the aliases or shrink the file")
        return loader.construct_document(root)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy YAML cannot be parsed: {exc}") from exc
    finally:
        loader.dispose()


class PolicyEngine:
    def __init__(self, config: dict, strict: Optional[bool] = None):
        if not isinstance(config, dict):
            raise PolicyError(f"a policy must be a mapping, got {type(config).__name__}")
        if "version" not in config:
            raise PolicyError("policy is missing required 'version' field")
        self._validate_structure(config)
        self._validate_options(config)
        #: built-in names plus the ones the policy declares under `custom_categories`
        self.known_categories: frozenset = self._declared_categories(config)
        self._validate_names(config, self.known_categories)
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
        self._admission_lock = threading.RLock()

    @classmethod
    def from_yaml(cls, path: str, strict: Optional[bool] = None) -> "PolicyEngine":
        if yaml is None:
            raise RuntimeError("pyyaml is required to load policy files: pip install pyyaml")
        data = load_policy_yaml(Path(path).read_text(encoding="utf-8"))
        return cls(data, strict=strict)

    @staticmethod
    def _validate_structure(config: dict) -> None:
        """Every section is a mapping and every list-valued field is a list of strings, at load time."""
        agents = config.get("agents", {})
        if not isinstance(agents, dict):
            raise PolicyError(f"'agents' must be a mapping of agent id to settings, got {type(agents).__name__}")
        sections = []
        if "default" in config:
            sections.append(("default", config["default"]))
        sections += [(f"agent '{name}'", cfg) for name, cfg in agents.items()]
        for where, cfg in sections:
            if not isinstance(cfg, dict):
                raise PolicyError(f"{where} must be a mapping of settings, got {type(cfg).__name__} {cfg!r}")
            for field in ("allowed_tools", "trifecta_exempt_tools", "state_change_allowed_tools"):
                if field in cfg:
                    string_list(cfg[field], f"'{field}' in {where}")
            cats = cfg.get("tool_categories", {})
            if not isinstance(cats, dict):
                raise PolicyError(f"'tool_categories' in {where} must be a mapping of tool name to a list of "
                                  f"categories, got {type(cats).__name__} {cats!r}")
            for tool, value in cats.items():
                if not isinstance(tool, str):
                    raise PolicyError(f"tool names in 'tool_categories' ({where}) must be strings, got {tool!r}")
                string_list(value, f"categories of tool '{tool}' in {where}")

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
    def _declared_categories(config: dict) -> frozenset:
        declared = string_list(config.get("custom_categories", []), "'custom_categories'")
        for name in declared:
            if name in BUILTIN_CATEGORIES:
                raise PolicyError(f"'custom_categories' lists {name!r}, which is already built in; remove it")
            if _CANONICAL_NAME.fullmatch(name) is None:
                raise PolicyError(
                    f"'custom_categories' entry {name!r} is not in the canonical form: lower_snake_case "
                    "(a-z, 0-9 and '_', starting with a letter, at most 64 characters)")
        return frozenset(BUILTIN_CATEGORIES | set(declared))

    @classmethod
    def _validate_names(cls, config: dict, known) -> None:
        for where, cfg in cls._sections(config):
            for tool, cats in (cfg.get("tool_categories") or {}).items():
                for name in cats:
                    if name not in known:
                        raise PolicyError(unknown_category_message(name, known, f"tool '{tool}' in {where}"))

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
        categories = call_site_list(categories, f"categories of tool '{tool}' at the call site")
        for name in categories:
            if name not in self.known_categories:
                raise PolicyError(unknown_category_message(name, self.known_categories,
                                                           f"tool '{tool}' at the call site"))
        # Every section that mentions the tool, either by labelling it or by allowing it. A section that
        # allows it without a label counts as "no categories" (None for the message).
        mentions = {}
        for where, cfg in self._sections({"default": self.default, "agents": self.agents}):
            cats = cfg.get("tool_categories") if isinstance(cfg.get("tool_categories"), dict) else {}
            if tool in cats:
                mentions[where] = ("labelled", frozenset(cats[tool]))
            elif tool in (cfg.get("allowed_tools") or []):
                mentions[where] = ("unlabelled", frozenset())
        if len({labels for _, labels in mentions.values()}) > 1:
            silent = [w for w, (how, _) in mentions.items() if how == "unlabelled"]
            labelled = {w: sorted(c) for w, (how, c) in mentions.items() if how == "labelled"}
            if silent and labelled:
                w_lab = next(iter(labelled))
                raise PolicyError(
                    f"tool '{tool}' is labelled in {w_lab} ({labelled[w_lab]}) but {silent[0]} allows it without "
                    f"labelling it, so the same function would be unclassified there. Add the same label under "
                    f"'tool_categories' in {silent[0]}, or remove it from that section's 'allowed_tools'.")
            shown = "; ".join(f"{w}: {sorted(c)}" for w, (_, c) in mentions.items())
            raise PolicyError(f"tool '{tool}' is labelled differently in different sections ({shown}). It is one "
                              "function, so it needs one label set; make the sections agree.")
        why = label_conflict(tool, categories)
        if why:
            raise PolicyError(f"{why} (at the call site)")
        mine = set(categories)
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

    def admit(self, session: SessionState, tool: str, extra_categories: Optional[list[str]] = None) -> Decision:
        """check() and, when the call is allowed, reserve its categories, as one step under a lock.

        Reserving at admission (not after the tool returns) is what stops two tools that start at the same time from
        both seeing an empty history. A reservation is never given back: the call that reserved it either completes
        or fails, and both already count toward the history (a failed call may have touched data first).
        """
        with self._admission_lock:
            decision = self.check(session, tool, extra_categories)
            if decision.allow:
                self.commit(session, tool, extra_categories)
            return decision

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
