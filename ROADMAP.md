# Roadmap

v0.1 is deliberately narrow: a hash-chained ledger, a lethal-trifecta
policy engine, signed agent-to-agent messages, and a best-effort process
sandbox. Below is what's next, roughly in the order the underlying
research report ranked them by (severity x how unmet the need still is).

## Near term

- **Container-based isolation.** Swap the subprocess sandbox for an
  actual containment boundary (Docker with dropped capabilities, or
  gVisor/Firecracker for stronger guarantees) as an opt-in `isolate="container"`
  mode, so `isolate=True` can eventually mean what people assume it means.
- **Redundant ledger custody.** Optional streaming of each record to
  append-only external storage (S3 Object Lock, a write-only collector
  service) as it's written, so `verify()`'s "nothing altered" guarantee
  is paired with an independent "nothing removed" guarantee.
- **Policy hot-reload + versioned snapshots.** Right now a policy change
  requires restarting the process; evidence records already capture
  `policy_version`, but there's no built-in way to pin/diff policy
  versions over time.
- **PyPI release** once the API has had a few real integrations shake
  out rough edges.

## Medium term

- **Public-key agent identity.** `agent_bridge.py` uses a pre-shared
  HMAC secret, which doesn't scale past "both sides are in the same
  trust domain." A public-key (e.g. Ed25519) scheme would let
  cross-organization agents verify each other without sharing a secret.
- **OpenTelemetry GenAI semantic-conventions export**, so evidence
  records can flow into existing observability stacks instead of only
  living in a standalone ledger file.
- **Regulatory field mapping.** A `--map ll144` / `--map eu-ai-act`
  style CLI flag that annotates ledger records with the specific
  clauses they support, instead of leaving that mapping to the reader.
- **Data & model supply-chain checks (ASI04).** Verifying model/prompt
  provenance is out of scope for v0.1's runtime guard; a separate
  companion tool is more likely than bolting it onto this one.

## Explicitly not planned (for now)

- **Prompt-injection content classification.** There are already
  dedicated products for this (see the research report's landscape
  chapter); auditrail's bet is that *constraining what a session can do*
  is a more durable defense than *detecting malicious text*, and the two
  are complementary rather than substitutes.
- **Becoming a hosted SaaS in v0.1.** The library stays usable
  standalone; a hosted dashboard/service is a possible later layer, not
  a prerequisite for the core to be useful.

Have an opinion on the ordering above, or a real integration that broke
in an interesting way? Open an issue -- this roadmap is meant to be
argued with.
