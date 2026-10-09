# Architecture

```
                          ┌─────────────────────────┐
  agent / LLM tool-use ──▶│   @guard.guarded_tool    │
  (Claude, GPT, an        │  ─────────────────────  │
  MCP server, your own    │  1. PolicyEngine.check() │──▶ deny? ─▶ ToolDenied
  orchestrator, ...)      │     (allow-list +        │     raised, logged,
                          │      lethal-trifecta)    │     real fn NEVER runs
                          │  2. if allow: run the    │
                          │     REAL wrapped tool    │──▶ your real function
                          │     (optionally isolated │     (file I/O, HTTP,
                          │      in a subprocess)    │      DB, sub-agent...)
                          │  3. Ledger.record(...)   │
                          └────────────┬─────────────┘
                                       │ append-only, hash-chained
                                       ▼
                          ┌─────────────────────────┐
                          │   evidence.jsonl          │
                          │   {seq, ts, agent_id,     │
                          │    tool, categories,      │
                          │    args_digest, decision, │
                          │    result_digest,         │
                          │    prev_hash, hash}       │
                          └────────────┬─────────────┘
                                       │
                              `auditrail verify` or
                              `Ledger(path).verify()`
                                       │
                                       ▼
                     independently provable: "nothing in
                     this file was altered after it was written"
```

For agent-to-agent calls specifically (one agent invoking another as a
tool), `agent_bridge.sign_message` / `verify_message` sit in front of the
same flow: the receiving agent only treats a message as authentic once
its HMAC signature, freshness window, and (optionally) nonce uniqueness
all check out.

## Why "categories," not "tools," drive the policy decision

A naive allow-list ("agent X may call tools A, B, C") says nothing about
*combinations*. The incidents this project is modeling on
(EchoLeak, Slack AI's indirect prompt injection, ForcedLeak in Salesforce
Agentforce, the GitHub MCP private-repo exfiltration disclosure) all have
the same shape: a single session ends up with (1) access to private data,
(2) exposure to attacker-influenceable content, and (3) a way to send
data out -- and any *one* of those three tools looked individually
harmless in isolation. `policy.py` tracks categories per session and
refuses to complete that trio, regardless of which specific tool would be
the third leg.

## Why the ledger stores digests, not raw payloads

A complete, centralized log of every tool call's real arguments and
results would itself become the highest-value target in the system (see:
the exposed DeepSeek database incident, which leaked exactly this kind of
data). `Ledger.record()` hashes arguments and results with SHA-256 and
stores only the digest. That's enough to *prove* a specific input/output
pair occurred (an auditor who already has the plaintext, from your own
systems, can hash it and confirm the match) without the ledger file
itself becoming sensitive data at rest.

## Full research context

This project's problem framing (why prompt injection resists a clean
fix, why "lethal trifecta" is the right unit of analysis, what OWASP's
Agentic Top 10 2026 actually says, and what's still structurally missing
in the market) comes out of a longer research report: incidents,
regulation, and a landscape/gap analysis of AI security and audit
tooling. Ask the maintainer for a copy if you want the full citations
behind the design choices above.

## v0.2: where the trust lives

```
 agent process                          recorder process (own OS user/host)        outside the operator's control
┌──────────────────────┐   append only  ┌───────────────────────────────┐          ┌───────────────────────┐
│ Guard + PolicyEngine │ ─────────────▶ │ Ledger (hash chain + Ed25519) │ anchors  │ witness: git repo,    │
│  - allow / deny      │  digests only  │ heartbeats every N s          │ ───────▶ │ timestamp service,    │
│  - workflow trifecta │  (no raw args) │ signs anchors                 │ (hashes) │ customer storage      │
│ RemoteLedger         │                │ holds the PRIVATE key         │          └──────────┬────────────┘
│  (no key, no read)   │                └───────────────────────────────┘                     │
└──────────────────────┘                                                                      ▼
        │ signed envelope (+ categories)                                      auditrail-verify (Rust, offline)
        ▼                                                                     ledger + PUBLIC key + witness copy
 other agent's Guard ── receipt ──▶ sender's ledger        → OK / TAMPERED_LEDGER / BAD_SIGNATURE /
 (both sides log; `reconcile` compares)                      TRUNCATED / REWRITTEN / HEARTBEAT_GAP / ...
```

Three separations carry the design, and each is a place it can fail:

1. **Agent vs. recorder.** The agent only appends digests; it cannot read, edit, or sign. This is
   worth something only if the recorder runs as a different OS user or host and the key file is not
   readable by the agent.
2. **Recorder vs. operator.** Signatures stop a rewrite by someone *without* the key. An operator who
   holds the key can still rewrite, which is why anchors exist.
3. **Operator vs. witness.** An anchor held by someone else turns "prove you did not rewrite it" into
   "show the copy you kept". It is only as independent as the witness.

What the architecture cannot give you is completeness: if a tool is not wrapped, or the agent holds an
outbound credential the guard does not mediate, nothing is recorded. Heartbeats show which tools *are*
wrapped and make a stopped recorder visible; closing the rest needs the agent to hold no credentials
except through the guard (see ROADMAP).

The byte-level format, hashing and signing rules are in [spec/evidence-format-v2.md](spec/evidence-format-v2.md).
