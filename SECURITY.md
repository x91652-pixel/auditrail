# Security model and scope

auditrail is an early-stage project (v0.2, no independent security review). This
document exists so nobody -- including us -- overestimates what it does. Each
claim in the "does" column is covered by at least one test (named in
[docs/STATUS.md](docs/STATUS.md)), **except for the cases listed under "Where the
tests do not reach" below**; every gap we know of is in the "does not" section. It maps features to the OWASP Top 10 for Agentic Applications 2026
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
| Independent *implementation* of the verifier (`verifier/`, Rust; **same author**) | -- | A separate implementation, checked against the same conformance vectors and fuzzed against the Python one, so the format does not depend on our Python. Both read files by the same strict rules (spec section 2). The same author wrote both, so this is a consistency check, not yet independent review. |
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
- **The trifecta rule is category-based and the categories are labelled by you.** A wrong label defeats it. A write action with no external-comm label (rerouting a shipment, issuing a refund) is not blocked by it. Two opt-in options reduce this (see "Opt-in hardening" below); they do not remove it, and the defaults are unchanged.
- **Workflow tracking needs the link.** Two sessions with different `trace_id`s and no signed message between them are still independent (the known gap in the simulation).
- **Messages need your key registry to be right.** Whoever controls the registry decides which key speaks for which agent. The v1 shared-secret HMAC remains for compatibility and **proves only "someone with the secret"**.
- **Replay protection is in memory by default.** `ReplayGuard` is per process and forgets nonces after its TTL (which must be at least the freshness window). `SqliteReplayGuard` shares the memory between processes **on one host**; it does nothing across hosts, and the SQLite file must not live on a network filesystem. A store you operate yourself is needed for a multi-host deployment.

**About isolation**

- **`isolate=True` is not a sandbox.** It is an OS subprocess that shares the filesystem (including `~/.aws`, `~/.ssh`, any credential file) and the network. It stops hangs and inherited environment variables, not a hostile tool. A real boundary needs a container or microVM (see ROADMAP).
- **The environment filter is an allow-list** (`PATH`, `TEMP`, locale, ... plus names you pass in `env_passthrough`). It does not look inside files or other channels.

**About scope**

- **No supply-chain verification (ASI04), no memory/context-poisoning detection (ASI06), no cascading-failure containment (ASI08)** beyond what the above gives.
- **No steganography detection.** There is no known technique that guarantees it; the ledger is an evidence layer for after-the-fact analysis, not a detector.
- **Not a certified compliance product.** Nothing here has had an independent audit. Do not represent its output as satisfying NYC Local Law 144, the EU AI Act, ISO/IEC 42001 or any other requirement without your own legal and compliance review.

## Where the tests do not reach

Stated so that "has a test" is not read as "is verified everywhere":

- **Platforms.** The maintainers' test runs so far were on Windows 11 with Python 3.11. Anything that is
  POSIX-specific has not been executed by us: the permission check on real files (`chmod` modes), the `fcntl`
  file-lock path, a recorder shut down with SIGTERM, and `anchor --push` on a system with a stricter git
  `safe.directory` policy. The pure functions behind them are tested; the end-to-end paths are not.
- **Constant-time token comparison.** A test shows the comparison goes through `hmac.compare_digest` on equal-length
  digests. Nothing measures timing.
- **Key rotation (Key custody, step 5).** "Anchor under both keys for an overlap" is a procedure we describe. There is
  no test that rotates a key and verifies across the overlap.
- **Timestamping services as a witness.** The anchors row lists one as an example of an independent copy; no
  timestamping witness is implemented (RFC 3161 is on the roadmap). Only file and git witnesses exist and are tested.
- **The release workflow** (`release.yml`) has never run on GitHub, so the prebuilt binaries, checksums and
  attestations described in the README are unproven. `verify --git-repo` through the CLI has no test of its own.
- **Tests that need the Rust binary** skip with an explicit reason when it is not built; a green run without it says
  nothing about Python/Rust agreement.
- **The Windows ACL check** reads only the broad groups (see the recorder row below); a loose permission it cannot
  see passes.

## Opt-in hardening: what it mitigates and what remains

Most of these are off unless you turn them on, so an existing policy is evaluated exactly as
before. **Four are behavior changes that apply by default** (labels that contradict each other, category names that are not known, the recorder's permission gate, and the same tool labelled differently by two agents) and are listed under "Behavior changes" below with the way back. "Mitigated" means the problem is smaller or louder, not that it is gone.

| Known problem | Option | What it now does | What still remains |
|---|---|---|---|
| A tool nobody labelled is invisible to the trifecta rule | `PolicyEngine(..., strict=True)` or `strict_classification: true` | A wrapped tool with no category (policy or call site) is refused before it runs and the refusal is recorded as `unclassified_tool`. An empty list does **not** count as a label; a harmless tool must say `internal`. Without strict mode a warning is emitted when the tool is wrapped. **Behavior change:** `internal` together with any other category on the same tool is refused with a `PolicyError` naming the tool and the categories, when the policy is loaded and again when the tool is wrapped (so a call-site label cannot contradict the policy). An empty list is still not a declaration. **Behavior change:** a category name must be a built-in one (`data_access`, `untrusted_input`, `external_comm`, `state_change`, `internal`, `agent_to_agent`) or be declared once in the policy's top-level `custom_categories`; any other spelling (`State_Change`, ` internal`, `state-change`, a typo) is a `PolicyError` at load and at the call site, with the closest known name suggested, in every mode. | **A wrong label is still believed.** A state-changing tool labelled `internal` runs (simulation attack 19). The engine cannot know what a function does. `internal` is a convention, not a verified fact. The warning is emitted once at wrap time, and only to whoever reads the output. The check compares labels with each other only: a tool labelled `internal` **alone** runs, whatever it does, because nothing can tell the label is false. **Declaring a custom category is not vetting it**: a wrong but declared name is accepted, and a category the engine has no rule for does nothing. Names are matched exactly; the check cannot know what a tool really does. |
| A write action with no external channel (refund, reroute) is not stopped | label the tool `state_change`; per agent `enforce_state_change_after_untrusted: true`, optional `state_change_allowed_tools` | A `state_change` tool is refused once its workflow has touched `untrusted_input`, unless explicitly listed. | **Only for tools you labelled `state_change`**, and only after *untrusted input was labelled as such*. A state change with no untrusted input first is allowed. A tool on the allow list is trusted completely. Splitting a workflow without a shared `trace_id` or signed message (simulation attack 11) still defeats it. It is a rule about *order*, not a judgement of whether the action is right: there is no approval step. |
| Replay protection is per process | `SqliteReplayGuard(path)` | One decision shared by all processes on a host; of N processes given the same message exactly one accepts it. Fails closed if the store cannot answer. | Single host only; SQLite on a network filesystem is unsafe; anyone who can write the file can erase nonces, so its permissions matter. The freshness window still bounds how long a nonce must be remembered. |
| The recorder is protected only by a shared token | constant-time token check; start-up permission check (refuses by default; `--allow-loose-permissions`) | The token is compared as fixed-length digests (a non-ASCII token now also works); non-string tokens are rejected. **Behavior change:** `auditrail recorder` refuses to start (exit code 2) when the signing key is readable by other accounts, or the ledger/anchors are writable by them. With `--allow-loose-permissions` the same findings are printed as warnings and it starts. A check that could not run (on Windows: PowerShell missing, failing or timing out) **also refuses to start**, because an unknown is treated as unsafe; with the flag it is printed as `NOT CHECKED` and the recorder starts. POSIX does not use PowerShell and is not affected. | **There is no socket file**: the recorder listens on a loopback TCP port, so *any local process* that knows the token can write, and anything that can read the environment or the agent's memory has the token. The token travels in clear text over loopback. The permission check cannot see who the agent runs as, and same OS user for agent and recorder defeats all of it. On Windows it reads the ACL through PowerShell and looks only at the broad groups (Everyone, Users, Authenticated Users, Guests, Anonymous): a key readable by one specific other account, or by a group that is not in that list, **passes**; if PowerShell is unavailable the check did not run and the start is refused unless you pass the flag. Passing the check is not evidence that the key is safe. |

### Behavior changes (these apply without opting in)

| Change | Effect | Way back |
|---|---|---|
| `internal` may not be combined with another category (policy load and tool wrapping) | A policy that labels one tool `internal` and also, say, `state_change` no longer loads; `guarded_tool` raises `PolicyError` for a contradicting call-site label. Previously both labels were accepted and the tool simply carried both. | Remove one of the two labels. There is no switch that re-allows the combination, on purpose: it would make `internal` a way to look classified. |
| `auditrail recorder` refuses to start with a loose key, ledger or anchors file, **or when the permission check could not run** | Exit code 2 and a message naming each file (or the reason the check failed), before anything is read from the key or written to the ledger. | Fix the permissions or the checker, or pass `--allow-loose-permissions`: loose permissions become warnings and an unchecked file is reported as `NOT CHECKED`. |
| A category name that is not built in or declared is refused (policy load, tool wrapping), in every mode | `State_Change`, `INTERNAL`, ` internal`, `state-change`, unknown names and typos raise `PolicyError` with the closest known name. Previously any string was accepted as a category, so a misspelling silently turned a rule off. | Declare your own names once: `custom_categories: [team_billing, ...]` (lower_snake_case) at the top level of the policy. There is no switch that skips the check: a name nobody declared is the typo this exists to catch, and declaring it is one line. |
| One tool labelled differently by two agent sections fails when it is wrapped (`guarded_tool`) | A tool is one function; if `agent a` says `[data_access]` and `agent b` says `[external_comm]` (or `[]`), `PolicyError` names both sections. Loading the policy alone is still fine. | Give the tool the same label set in every section that lists it. |

Not changed: an empty category list is still not a declaration in strict mode, and without strict mode a tool with no
category still runs (with a warning when it is wrapped).


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
Fuzzing the two verifiers against each other then found, and v0.2 fixes, readers that disagreed on odd input: a Python crash on non-UTF-8 files; signatures that could be altered with whitespace or capitals and still verify (`bytes.fromhex` is lenient); `true` accepted as the integer 1; `NaN`, `-0` and huge integers accepted by one reader; Unicode line breaks splitting records differently; lone surrogates crashing one reader. It also fixes: v0.1 ledgers being reported as tampered by the strict v2 reading rules (v0.1 stored a float `duration_ms`; they now get a distinct `LEGACY_FORMAT` result and an explicit, Python-only `verify --legacy-v01` hash-chain check, which is as weak as v0.1 always was). It also fixes: the deny-list environment filter (now allow-list), a printing tool
corrupting isolated results, raw error text reaching the ledger, concurrent
writers corrupting the chain, and heartbeat-less silent gaps.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
Security Advisories on this repository (Security tab -> "Report a
vulnerability"), rather than opening a public issue.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for what is planned to close the gaps above, and
[docs/spec/evidence-format-v2.md](docs/spec/evidence-format-v2.md) for the format.
