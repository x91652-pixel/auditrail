# Security model and scope

auditrail is an early-stage proof-of-concept (v0.1). This document exists
so nobody -- including us -- overestimates what it currently does. It
maps what's implemented to the OWASP Top 10 for Agentic Applications
2026 (ASI01-ASI10) and to the "lethal trifecta" framework (Simon
Willison), and lists what is explicitly out of scope for this version.

## What v0.1 actually does

| Feature | OWASP ASI mapping | What it proves |
|---|---|---|
| Hash-chained evidence ledger (`ledger.py`) | Supports incident response / forensics for any ASI category | A ledger file's records have not been altered, reordered, or partially truncated *after* being written. `verify()` recomputes the chain independently -- it does not trust the process that produced the file. |
| Lethal-trifecta policy engine (`policy.py`) | ASI02 (Tool Misuse), ASI03 (Agent Identity & Privilege Abuse) | Blocks a tool call, *before it executes*, if allowing it would let a single agent session hold data-access + untrusted-input + external-comm capability simultaneously -- the shape behind EchoLeak, Slack AI, ForcedLeak, and the GitHub MCP disclosure. |
| Signed inter-agent messages (`agent_bridge.py`) | ASI07 (Insecure Inter-Agent Communication) | An HMAC-SHA256 signature plus a timestamp freshness window plus optional nonce tracking detects a forged or replayed message between agents. |
| Process-isolated tool execution (`sandbox.py`, `isolate=True`) | Partial mitigation for ASI05 (Unexpected Code Execution) | A tool call runs in a subprocess with secret-looking environment variables stripped and a wall-clock timeout, so a hung or runaway call cannot block the caller or silently inherit ambient API keys. |

## What v0.1 explicitly does NOT do

Be skeptical of any tool (including this one) that doesn't say this part out loud.

- **Not a containment boundary.** `isolate=True` is a plain OS subprocess, not a container, VM, or gVisor/Firecracker-style sandbox. It shares the filesystem and network with the host. It reduces blast radius from bugs and hangs; it does not stop a genuinely adversarial tool from reading local files or reaching the network. Real isolation is tracked in ROADMAP.md.
- **No supply-chain verification (ASI04).** auditrail does not check whether the model, prompts, or dependencies your agent uses have been tampered with.
- **No memory/context poisoning detection (ASI06).** If an agent's long-term memory or a RAG index is already poisoned, auditrail will faithfully log the poisoned decisions -- it doesn't detect the poisoning itself.
- **No cascading-failure containment (ASI08)** across a multi-agent system beyond the pairwise signature check in `agent_bridge.py`.
- **No prompt-injection detection.** auditrail does not classify or block malicious *content*; it constrains what a session is *allowed to do* regardless of what the model was tricked into wanting to do. Pair it with an input/output classifier if you need that layer too.
- **The ledger does not stop a determined operator from deleting the whole file.** `verify()` proves *the records present are internally consistent*; it does not prove *nothing was ever removed from the end*. Production use needs redundant custody -- ship records to append-only storage (e.g. object storage with object-lock, or a separate write-only collector) as they're written. See `tests/test_ledger.py::test_truncating_the_tail_is_not_silently_accepted_as_more_records` for exactly what is and isn't guaranteed.
- **Not a certified compliance product.** Nothing here has been through an independent audit. Do not represent output from this tool as satisfying NYC Local Law 144, the EU AI Act, ISO/IEC 42001, or any other specific legal requirement without your own legal and compliance review.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
Security Advisories on this repository (Security tab → "Report a
vulnerability"), rather than opening a public issue.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for what's planned to close the gaps above.
