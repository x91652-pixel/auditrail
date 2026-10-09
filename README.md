# auditrail

**Tamper-evident audit trails and a "lethal trifecta" policy guard for AI agents.**

`pip install -e .` today; `pip install auditrail` once it's on PyPI (not yet -- see Status below).

[![test](https://github.com/x91652-pixel/auditrail/actions/workflows/test.yml/badge.svg)](https://github.com/x91652-pixel/auditrail/actions/workflows/test.yml)
![status](https://img.shields.io/badge/status-v0.2_early-orange)
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

## What it actually does (v0.2)

auditrail is the smallest component that lets someone who does **not** trust you
check what an agent did. It is a library plus a standalone verifier, not a
governance platform; it is meant to sit next to the gateways and guardrails you
already use.

- **Signed, hash-chained ledger.** Every record is chained to the previous one
  and signed (Ed25519) by a recorder key the agent never sees. Editing a record
  and recomputing the hashes -- which defeated v0.1 -- now fails verification.
- **Anchors and witnesses.** The ledger head is published (signed) to a place the
  operator cannot rewrite alone; a verifier with only the witness copy can then
  prove nothing before it was removed or changed.
- **Heartbeats.** The recorder periodically writes which tools it wraps, a hash of
  the policy in force, and how many calls it intercepted vs. recorded, so silent
  periods, tool/policy changes, and calls that ran without evidence show up.
- **Independent verifier.** `verifier/` is a separate Rust program, written from the
  [public format spec](docs/spec/evidence-format-v2.md) and tested against the same
  conformance vectors as the Python code. One offline binary, no network.
- **Lethal-trifecta policy by workflow.** A call that would complete
  data-access + untrusted-input + external-comm is refused *before it runs*, counted
  across a whole workflow (shared `trace_id`, or agents linked by a signed message
  that carries the sender's categories), not just one session.
- **Per-agent signed messages with receipts.** Each agent has its own key, so a
  message is attributable and bound to its recipient. Both sides log it and
  `auditrail reconcile` finds a message only one side recorded.
- **Process-isolated execution** (`isolate=True`): allow-listed environment and a
  timeout. Reduces accidents; it is **not** a security sandbox.

What it deliberately does **not** do -- detect prompt injection, prove that
unwrapped tools stayed quiet, protect you if the recorder key is stolen, or certify
compliance -- is in [SECURITY.md](SECURITY.md). Read that before deciding whether
it fits your threat model.

## Evidence the operator cannot quietly rewrite

```bash
# 1. a recorder key, kept where the agent process cannot read it
auditrail keygen --out keys/recorder

# 2. run the recorder as its own process (ideally its own OS user or host);
#    it holds the key and the ledger, and agents can only append through a socket
export AUDITRAIL_RECORDER_TOKEN=change-me
auditrail recorder --ledger evidence.jsonl --key keys/recorder.key \
    --policy policies/example_policy.yaml --anchors anchors.jsonl \
    --git-repo ../witness            # anchors are committed here; you push it somewhere you don't control
```

```python
from auditrail import Guard, PolicyEngine, RemoteLedger
guard = Guard(PolicyEngine.from_yaml("policies/example_policy.yaml"), RemoteLedger(port=8765))
guard.start_heartbeats()             # the agent's own "still wrapped" signal
```

```bash
# 3. anyone, offline, with only the PUBLIC key and a witness copy:
auditrail-verify evidence.jsonl --pubkey keys/recorder.pub --witness witness-copy.jsonl --max-gap 120
# (or `auditrail verify ...` with the same flags in Python)
```

The verifier prints `OK` only with a list of what it did **not** check (no key
given, no witness, no heartbeat limit, records after the last anchor).

## Anchoring (protocol v1)

`verify` only proves the ledger is internally consistent: someone who rewrites
the whole ledger, or cuts off its tail, still passes it. Anchoring periodically
records the chain head (sequence number and hash, no tool arguments or results)
and publishes it to a witness outside the ledger owner's sole control. The full
specification is in `auditrail-docs/錨定協定.md`; the signed (v2) form is in [docs/spec/evidence-format-v2.md](docs/spec/evidence-format-v2.md).

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
so anchor hashes should also be copied to a third party periodically. Anchors made
with `--key` are signed (anchor_version 2, see [the format spec](docs/spec/evidence-format-v2.md));
Merkle proofs and RFC 3161 timestamps are not implemented yet.

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

v0.2 -- early, unreleased on PyPI, not yet used in production anywhere, no
independent security review. The format is a draft: expect changes until a second
team has implemented it. Issues, and especially "this
broke when I tried it against a real agent" reports, are exactly what
this stage needs. See [ROADMAP.md](ROADMAP.md).

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

All 253 Python tests are deterministic and require no network access or API key
(one demo scenario attempts a single real HTTP call and skips gracefully
if you're offline). The Rust parts have their own tests: `cd verifier && cargo test`
(runs every [conformance vector](docs/spec/vectors) through the independent verifier) and
`cd dashboard && cargo test`. Python tests that compare against the Rust verifier are
skipped until you run `cd verifier && cargo build --release`.

The two verifiers are also fuzzed against each other (`tests/test_fuzz.py`, Hypothesis; raise the sample size with
`AUDITRAIL_FUZZ_EXAMPLES=500`): random ledgers, field edits, raw byte corruption, re-hash attacks, truncation and garbage
must give the same status in Python and Rust, and never a crash. `tests/test_reader_agreement.py` pins down the odd
inputs (non-UTF-8, `-0`, `true` as an integer, signatures with a space, ...) one by one.

To see the attack simulation (a fictional logistics company with five
agents, 9 normal operations and 16 attacks, including the known gaps):

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
