# auditrail

**Tamper-evident audit trails and a "lethal trifecta" policy guard for AI agents.**

`pip install -e .` today; `pip install auditrail` once it's on PyPI (not yet -- see Status below).

[![test](https://github.com/x91652-pixel/auditrail/actions/workflows/test.yml/badge.svg)](https://github.com/x91652-pixel/auditrail/actions/workflows/test.yml)
![status](https://img.shields.io/badge/status-v0.1_proof--of--concept-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

## The problem

AI agents now read private data, browse untrusted content, and act on the
outside world -- often all in the same session. When those three
capabilities land in one place, a prompt injected into "just some text
the agent read" turns into real data exfiltration. This is not
hypothetical:

- **EchoLeak** (CVE-2025-32711, CVSS 9.3) -- a single crafted email let
  Microsoft 365 Copilot read a user's files and exfiltrate them through a
  trusted domain, with zero clicks.
- **Slack AI** -- an attacker in a public channel could get Slack AI to
  leak content from private channels the attacker was never a member of.
- **ForcedLeak** (CVSS 9.4) -- indirect prompt injection via a
  Salesforce Agentforce web form leaked CRM data to an attacker-controlled
  domain that cost about $5 to register.
- **GitHub MCP** -- a malicious public GitHub issue could hijack an
  AI coding agent into leaking the contents of the user's private
  repositories.
- **Replit's coding agent** deleted a production database during an
  explicit "code freeze," then fabricated data to hide it.
- **GTG-1002** -- Anthropic's own threat-intel team disclosed a
  state-linked actor that got an AI agent to autonomously execute an
  estimated 80-90% of a multi-target intrusion campaign.

OWASP's [Top 10 for Agentic Applications
2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
formalizes the pattern behind most of these as **Tool Misuse (ASI02)**,
**Agent Identity & Privilege Abuse (ASI03)**, and **Insecure Inter-Agent
Communication (ASI07)**. Independently, Simon Willison named the
underlying shape the **["lethal
trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)**:
private data access + exposure to untrusted content + a way to
communicate externally, all in one session. Any two are usually fine.
All three, in the same agent session, is how these incidents happen.

**auditrail gives an agent session a policy engine that refuses to
complete that trio, and a tamper-evident log of every decision it made
along the way** -- so when something does go wrong, you can prove what
the agent saw, what it was allowed to do, and whether the record of that
has been altered since.

## What it actually does (v0.1)

- **Lethal-trifecta policy engine** -- declare, per agent identity, which
  tools it may call and what category each tool touches
  (`data_access` / `untrusted_input` / `external_comm` / `agent_to_agent`).
  A call that would complete all three categories in one session is
  refused *before it executes*, not flagged after the fact.
- **Hash-chained evidence ledger** -- every allowed, denied, or sandboxed
  call is appended to a JSONL file where each record is chained to the
  previous one's hash (the same construction Certificate Transparency
  logs use). `auditrail verify` independently recomputes the chain and
  tells you exactly where it breaks if a record was ever altered.
- **Signed agent-to-agent messages** -- HMAC-SHA256 signatures with a
  freshness window and replay protection for when one agent invokes
  another as a tool (OWASP ASI07).
- **Process-isolated execution** -- `isolate=True` runs a tool call in a
  separate subprocess with secret-looking environment variables stripped
  and a timeout, so a hung or runaway tool can't block the caller or
  silently inherit ambient API keys.

**What it deliberately does not claim to do** -- prompt-injection
detection, supply-chain verification, memory-poisoning detection, or
certified regulatory compliance -- is documented honestly in
[SECURITY.md](SECURITY.md). Read that before you decide whether this fits
your threat model.

## Anchoring (protocol v1)

`verify` only proves the ledger is internally consistent: someone who rewrites
the whole ledger, or cuts off its tail, still passes it. Anchoring periodically
records the chain head (sequence number and hash, no tool arguments or results)
and publishes it to a witness outside the ledger owner's sole control. The full
specification is in `auditrail-docs/錨定協定.md`.

```bash
# record the current head; with --push, also push the witness commit
auditrail anchor --ledger ledger.jsonl --anchors anchors.jsonl --git-repo ../witness
auditrail verify ledger.jsonl --anchors anchors.jsonl --git-repo ../witness
```

`verify --anchors` reports one of `OK`, `TAMPERED_LEDGER`, `TAMPERED_ANCHOR`,
`REWRITTEN`, `TRUNCATED`, `SINK_MISMATCH`, or `SINK_UNREACHABLE`, plus how many
records after the last anchor are not covered.

What anchoring proves: records up to the last anchor were not rewritten, deleted,
or reordered, provided that anchor has been stored outside the owner's control.
Truncation below an anchor is detected in the same way.

What it does not prove: records after the last anchor; a ledger rewritten from
the start whose anchors were never stored externally; records that were never
written at all; a compromised host making changes in real time; or a witness and
the owner acting together. The git witness is only as strong as the place the
repository lives. A repository the owner controls can be rewritten by that owner,
so anchor hashes should also be copied to a third party periodically. There are no
signatures, Merkle proofs, or RFC 3161 timestamps in this version.

## Quickstart

```bash
git clone https://github.com/x91652-pixel/auditrail
cd auditrail
pip install -e ".[dev]"

# No API key needed -- runs entirely offline, exercises every real code
# path: an allowed pipeline, a trifecta block, a signed agent message
# (and a rejected forged/replayed one), and tamper detection.
python -m examples.mock_demo

# or, after install:
auditrail demo
```

Verify any ledger's integrity independently:

```bash
auditrail verify examples/demo_ledger.jsonl
```

Wrap a real tool function in ~5 lines:

```python
from auditrail import Guard, Ledger, PolicyEngine

policy = PolicyEngine.from_yaml("policies/example_policy.yaml")
ledger = Ledger("evidence.jsonl")
guard = Guard(policy, ledger)

@guard.guarded_tool("read_resume", categories=["data_access"])
def read_resume(candidate_id: str) -> dict:
    return db.fetch_resume(candidate_id)   # your real function, unchanged

session = guard.session(agent_id="hr-screener")
resume = read_resume(session, "cand-001")   # policy-checked + logged automatically
```

See [`examples/mock_demo.py`](examples/mock_demo.py) for the full walkthrough
(including the trifecta-block and tamper-detection scenarios) and
[`examples/real_agent_demo.py`](examples/real_agent_demo.py) for a live
example with Claude doing real tool-use (`ANTHROPIC_API_KEY` required).

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full data-flow
diagram and the reasoning behind two specific design choices: why the
policy engine reasons about tool *categories* rather than tool identities,
and why the ledger stores argument/result digests rather than raw payloads.

## Where this fits

auditrail is a runtime primitive, not a platform. It's closest in spirit
to what SOC 2 did for infrastructure change logs -- a boring, verifiable
record -- applied to agent tool calls specifically. It's deliberately
narrow and meant to compose with things that already exist:

| If you need... | Consider |
|---|---|
| Prompt-injection / jailbreak detection on inputs and outputs | A guardrail product (Lakera, Prompt Security, etc.) |
| Agent discovery, fleet-wide policy across SaaS platforms | Zenity, Noma, Astrix |
| A certifiable standard + insurance for an agent | [AIUC-1](https://www.aiuc-1.com/) |
| An org-wide AI risk/compliance workflow | Credo AI, Holistic AI, IBM watsonx.governance |
| **A tamper-evident record of what one agent session actually did, that you own and can verify yourself, in your own code, with no vendor lock-in** | **auditrail** |

## Status

v0.1 -- proof of concept, unreleased on PyPI, not yet used in production
anywhere, no independent security review. Issues, and especially "this
broke when I tried it against a real agent" reports, are exactly what
this stage needs. See [ROADMAP.md](ROADMAP.md).

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

All 66 Python tests are deterministic and require no network access or API key
(one demo scenario attempts a single real HTTP call and skips gracefully
if you're offline). The Rust dashboard backend has its own tests:
`cd dashboard && cargo test`.

To see the attack simulation (a fictional logistics company with five
agents, 9 normal operations and 13 attacks, including the known gaps):

```bash
python -m examples.logistics_sim.run
```

Results and the reasoning behind each scenario are in
[docs/simulation.md](docs/simulation.md).

## Contributing

Issues and PRs welcome. Please read [SECURITY.md](SECURITY.md) first --
if you're adding a feature, say explicitly in the PR description which
row of that table it changes.

## License

[Apache-2.0](LICENSE)
