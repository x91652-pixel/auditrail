# Security model and scope

auditrail is an early-stage project (v0.2, no independent security review). This
document exists so nobody -- including us -- overestimates what it does. Every
claim in the "does" column has a test; every gap we know of is in the "does not"
section. It maps features to the OWASP Top 10 for Agentic Applications 2026
(ASI01-ASI10) and to the "lethal trifecta" framework (Simon Willison).

**The one-sentence version:** auditrail makes a record of what an agent did that
the operator cannot quietly rewrite, *if you keep the signing key and a witness
copy out of the operator's reach* -- and it tells you plainly what it did not check.

## What v0.2 does

| Feature | Maps to | What it proves, and the condition |
|---|---|---|
| Hash-chained ledger (`ledger.py`) | forensics for any ASI category | Records were not edited, reordered or inserted **by someone who did not also recompute the hashes**. On its own this is tamper-*evident* only against accidents. |
| Ed25519-signed records (`keys.py`, `recorder.py`) | evidence integrity | A rewrite also needs the recorder's private key. **Holds only if the agent and the operator cannot read that key** (see "Key custody"). Verified with `verify --pubkey`; without a key the verifier says signatures were not checked. |
| Anchors + witness (`anchor.py`) | evidence integrity | Records up to the last anchor were not removed or rewritten, **if a copy of the anchor lives somewhere the operator cannot alter** (public git repo, timestamping service, customer storage). A verifier holding only the witness copy needs nothing from the operator. |
| Heartbeats (`Guard.heartbeat`, recorder) | completeness (partial) | Shows silent periods, tool-list and policy changes over time, and any call a writer intercepted but failed to record. It covers **only wrapped tools**. |
| Independent verifier (`verifier/`, Rust) | -- | A separate implementation, checked against the same conformance vectors, so the format does not depend on our Python. |
| Lethal-trifecta policy engine (`policy.py`) | ASI02, ASI03 | Blocks a tool call *before it runs* if it would complete data-access + untrusted-input + external-comm within one **workflow**: sessions that share a `trace_id`, or agents linked by a signed message that carries the sender's categories. |
| Per-agent Ed25519 messages, receipts, `reconcile` | ASI07 | A message is attributable to one agent (not "anyone with the shared secret"), is bound to its recipient, and both sides' ledgers can be cross-checked for a message only one side recorded. |
| Process-isolated tools (`isolate=True`) | partial ASI05 | Runs a call in a subprocess with an **allow-listed** environment and a timeout. Reduces accidents and ambient-secret leakage. |

## What v0.2 does NOT do

Be skeptical of any tool (including this one) that does not say this part out loud.

**About the evidence**

- **It cannot prove a tool call was recorded if the tool was never wrapped.** Heartbeats list only wrapped tools. Completeness needs an architecture in which the agent holds no outbound credential except through the guard, plus cross-checking with the called system's own logs. auditrail gives you the pieces, not that architecture.
- **Records after the last anchor are not covered.** `verify` reports exactly how many.
- **Nothing helps if the recorder host or key is compromised.** `auditrail recorder` is a separate *process*. Running it as the same OS user as the agent protects against the agent's code, not against anyone who can read that user's files. Use a separate OS user, host, or KMS/TPM.
- **The witness must be independent.** An anchor only the operator holds is just a line the operator can delete. Colluding witnesses defeat it.
- **Anchors you never publish prove nothing.** `anchor` without `--git-repo`/`--witness-file` is local only, and says so.
- **No dependency on trusted time.** Timestamps are the recorder's clock; a timestamping (RFC 3161) witness is not implemented yet.
- **Args and results are stored as digests only.** That protects privacy and also means the ledger cannot reconstruct what was said. Encrypted retention is not implemented.

**About the policy and messages**

- **No prompt-injection detection, and none of the content of a message is judged.** A signed message can carry an injection; signatures prove origin, not safety.
- **The trifecta rule is category-based and the categories are labelled by you.** A wrong label defeats it. A write action with no external-comm label (rerouting a shipment, issuing a refund) is not blocked by it.
- **Workflow tracking needs the link.** Two sessions with different `trace_id`s and no signed message between them are still independent (the known gap in the simulation).
- **Messages need your key registry to be right.** Whoever controls the registry decides which key speaks for which agent. The v1 shared-secret HMAC remains for compatibility and **proves only "someone with the secret"**.
- **Replay protection is in memory.** `ReplayGuard` is per process and forgets nonces after its TTL (which must be at least the freshness window). Multi-process deployments need a shared store.

**About isolation**

- **`isolate=True` is not a sandbox.** It is an OS subprocess that shares the filesystem (including `~/.aws`, `~/.ssh`, any credential file) and the network. It stops hangs and inherited environment variables, not a hostile tool. A real boundary needs a container or microVM (see ROADMAP).
- **The environment filter is an allow-list** (`PATH`, `TEMP`, locale, ... plus names you pass in `env_passthrough`). It does not look inside files or other channels.

**About scope**

- **No supply-chain verification (ASI04), no memory/context-poisoning detection (ASI06), no cascading-failure containment (ASI08)** beyond what the above gives.
- **No steganography detection.** There is no known technique that guarantees it; the ledger is an evidence layer for after-the-fact analysis, not a detector.
- **Not a certified compliance product.** Nothing here has had an independent audit. Do not represent its output as satisfying NYC Local Law 144, the EU AI Act, ISO/IEC 42001 or any other requirement without your own legal and compliance review.

## Key custody (read this before trusting a signature)

1. Generate the recorder key where the agent cannot read it: `auditrail keygen --out keys/recorder`.
2. Run the recorder as its own process/OS user (`auditrail recorder --key ... --ledger ...`). Agents use `RemoteLedger`, which can only append and never sees the key.
3. Publish the **public** key (`recorder.pub`) with the first anchor, somewhere the operator cannot silently change. Verifiers pass it with `--pubkey`.
4. Publish anchors to a witness at a cadence that bounds how much tail you accept losing.
5. Rotate by anchoring under both keys for an overlap, then retire the old one.

## Version history of this document's claims

v0.1 said `verify()` "does not trust the process that produced the file". That was
wrong: a plain hash chain can be recomputed by anyone who can write the file
(demonstrated by `tests/test_signed_evidence.py::test_rewrite_and_rehash_passes_without_keys_but_fails_with_signatures`).
v0.2 fixes that with signatures and anchors and states the remaining conditions above.
It also fixes: the deny-list environment filter (now allow-list), a printing tool
corrupting isolated results, raw error text reaching the ledger, concurrent
writers corrupting the chain, and heartbeat-less silent gaps.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
Security Advisories on this repository (Security tab -> "Report a
vulnerability"), rather than opening a public issue.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for what is planned to close the gaps above, and
[docs/spec/evidence-format-v2.md](docs/spec/evidence-format-v2.md) for the format.
