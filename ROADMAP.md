# Roadmap

v0.2 closes the biggest gap in v0.1: a hash chain anyone with write access could
recompute. It now has recorder signatures, signed anchors with a witness, heartbeats,
an independent verifier, workflow-level policy, and per-agent signed messages.
What is left is mostly about *where the trust lives* and *what the evidence covers*.

## Done in v0.2

- Ed25519-signed records and anchors; the verifier requires them when given a key.
- `auditrail recorder` / `RemoteLedger`: the key and ledger live in a separate process.
- Heartbeats (wrapped tools, policy hash, intercepted-vs-recorded counts) and gap checks.
- Anchors to a git or file witness; verification from a witness copy alone.
- Independent Rust verifier and a public format spec with ten conformance vectors.
- Trifecta tracking per workflow, and signed messages that carry categories.
- Per-agent keys, receipts, and `reconcile` for two-sided cross-checking.
- Isolation environment is an allow-list; tool output cannot corrupt or forge a result.
- Error text is a digest by default; the ledger is safe for concurrent writers.

## Next (in this order, and each one needs a user or a reviewer to be worth building)

1. **Independent review of the format and recorder.** Nothing here has been audited.
   A second implementation of the verifier by someone else is worth more than any feature.
2. **One real witness beyond git.** An RFC 3161 timestamp or a transparency-log entry for
   anchors, so a witness is not only "a repository the operator might also control".
3. **Guard-gate architecture helper.** Completeness needs the agent to hold *no* outbound
   credential except through the guard. A reference deployment (proxy that holds the
   credentials, recorder as another OS user) turns "unwrapped tools" from a footnote into
   something you can test.
4. **Reconcile against the called system.** Import the other side's log (API provider,
   SaaS audit log) and report calls the ledger never recorded.
5. **Merkle tree and consistency proofs.** Single-record inclusion proofs and
   checkpoints, so a verifier does not need the whole file. Only worth it at volume.
6. **Container isolation** (`isolate="container"`): Docker with dropped capabilities, or
   gVisor/Firecracker. Until then `isolate=True` is blast-radius reduction, not a boundary.
7. **Optional encrypted retention of arguments/results**, chosen by the customer, for
   forensics that digests cannot support.
8. **Shared replay store** (Redis or a database) for multi-process agents.

## Exploring (needs interviews before any code)

- Whether auditors, security leads, or agent-product teams will actually pay, and for what.
  The stop condition and the interview plan are in the positioning paper.
- Agent-to-agent evidence as the first wedge: only if a real two-agent deployment turns up.
- Robot fleets: an independent recorder subscribing to a fleet-interop message bus
  (e.g. VDA 5050 over MQTT) is plausible; it needs the standard's signing story checked first.
  High-frequency control loops and hardware roots of trust are out of scope.

## Explicitly not planned

- **Prompt-injection or steganography detection.** There are dedicated products, and for
  steganography there is no technique with a guarantee. auditrail constrains what a
  session can *do* and keeps evidence for after-the-fact analysis.
- **Becoming a hosted platform.** The library and verifier stay usable standalone.
- **Claiming compliance.** Mapping fields to regulation clauses may come; certification will not.

Have an opinion on the ordering, or a real integration that broke in an interesting
way? Open an issue -- this roadmap is meant to be argued with.
