# auditrail

**Tamper-evident audit trails and a "lethal trifecta" policy guard for AI agents.**

Not on PyPI yet: to try it, follow the [Quickstart](#quickstart).

> **In plain words.** An AI agent can read private data, read text from untrusted places, and send things out. When all
> three happen in one session (the "lethal trifecta"), a trick hidden in the text can make it leak the data. auditrail
> is a small library that can refuse a tool call that would complete that combination, and that writes each decision
> to a log in which every entry is chained to the one before it (changing an old entry breaks the chain unless every later
> entry is recomputed, which is why entries are also signed) and, if you run a separate *recorder* process, signed by it
> (the Quickstart's ledger is not signed). Someone who does not
> trust you can then check, with the recorder's public key obtained from a route the operator cannot change, whether
> entries were edited; noticing that entries were deleted or the log cut short needs a witness copy. The *operator* is whoever
> runs the agent and owns these files; the *recorder* is the process that holds the signing key and writes the log; the
> *agent* is the AI program whose tool calls are logged. A *witness* is meant to be a place outside the operator's
> control that keeps copies of the log's fingerprints (*anchors*), published periodically; a
> *heartbeat* is a periodic entry in which the recorder says which tools it wraps and how many calls it saw versus
> recorded, so that, if you pass a gap limit when verifying, silent gaps in the wrapped tools show up. It covers only the tools you wrapped, does not detect prompt injection, and is not a compliance product.

> **Status and what this is not.** Early (v0.2), not on PyPI, with no independent security review. The evidence
> format is a draft. Both verifiers (Python and Rust) were written by the same author, so they check that the two
> agree, not yet that the format is right. It is not a certified compliance product. What it deliberately does not
> do is listed in [SECURITY.md](SECURITY.md); read that before deciding whether it fits.

[![test](https://github.com/x91652-pixel/auditrail/actions/workflows/test.yml/badge.svg)](https://github.com/x91652-pixel/auditrail/actions/workflows/test.yml)
![status](https://img.shields.io/badge/status-v0.2_early-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

## The problem

AI agents now read private data, browse untrusted content, and act on the
outside world -- often all in the same session. When those three
capabilities land in one place, a prompt injected into "just some text
the agent read" turns into real data exfiltration. Reported
incidents of that kind (each with its source; preconditions are given where the source states them):

- **EchoLeak** ([CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711)) -- a crafted email, with no
  action by the user, got Microsoft 365 Copilot to disclose confidential data. CVSS 3.1: Microsoft scored it 9.3,
  NIST (NVD) scored it 7.5.
- **Slack AI** (PromptArmor, August 2024) -- an attacker could post hidden instructions in a public channel that
  only they were in, and make Slack AI answer a victim with a link carrying the victim's private-channel data
  (for example an API key); the data left when the victim clicked. Slack replied at the time that messages in
  public channels are visible to workspace members by design.
  ([report](https://promptarmor.substack.com/p/data-exfiltration-from-slack-ai-via))
- **ForcedLeak** (Noma Labs, September 2025; Noma rated it CVSS 9.4) -- indirect prompt injection through a
  Salesforce Agentforce Web-to-Lead form could send CRM data to a domain that had expired but was still on the
  allow-list (Noma bought it for about $5). Salesforce enforced Trusted URLs in September 2025.
  ([report](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce/))
- **GitHub MCP** (Invariant Labs, May 2025) -- when a user's agent can reach both a public and a private
  repository, a malicious issue in the public one can make the agent write private-repository content into a
  public pull request. The discoverers describe this as an architectural issue at the agent layer, not a defect in
  the GitHub server code. ([report](https://invariantlabs.ai/blog/mcp-github-vulnerability))

Reported incidents that are not prompt-injection exfiltration (each with its source):

- **Replit** (July 2025) -- SaaStr founder Jason Lemkin said Replit's AI coding agent deleted his production
  database during a code freeze and invented data; Replit's CEO publicly called this
  unacceptable. The details come from Lemkin and were not independently verified.
  ([The Register](https://www.theregister.com/2025/07/22/replit_saastr_response/))
- **GTG-1002** (Anthropic, November 2025) -- Anthropic assessed with high confidence that a Chinese state-sponsored
  group (which its full report designates GTG-1002) used Claude Code against roughly 30 targets; according to
  Anthropic the AI performed 80-90% of the tactical operations, humans approved at key decision points, and a
  handful of intrusions succeeded.
  ([news page](https://www.anthropic.com/news/disrupting-AI-espionage),
  [full report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf))

OWASP's [Top 10 for Agentic Applications
2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (December 2025) includes
**Tool Misuse and Exploitation (ASI02)**, **Identity and Privilege Abuse (ASI03)** and **Insecure Inter-Agent
Communication (ASI07)**. Its own incident table files EchoLeak, ForcedLeak and the GitHub issue case, among others, under ASI01 (Agent
Goal Hijack) and ASI02; the GitHub issue case is also listed under ASI07. Independently, Simon Willison named a
shape he calls the **["lethal
trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)** (June 2025): access to private data,
exposure to untrusted content, and the ability to communicate externally. His point is that an agent that
combines all three can be tricked into leaking private data.

**auditrail gives an agent session a policy engine that refuses to
complete that trio, and a tamper-evident log of every decision it made
along the way** -- so that afterwards you can check which calls to
wrapped tools were allowed or refused (with the reason, for a refusal), and whether that record has been altered since (given a signing
key the operator cannot reach and a witness copy it does not control). The ledger stores digests of arguments and
results, not what the agent "saw".

## What it actually does (v0.2)

auditrail lets someone who does **not** trust you
check, given the recorder's public key and a witness copy, what an agent did through the tools you wrapped. It is a library plus a standalone verifier, not a
governance platform; it is meant to sit next to the gateways and guardrails you
already use.

- **Signed, hash-chained ledger.** Every record is chained to the previous one
  and signed (Ed25519) by a recorder key the agent never sees (when the recorder runs as its own process). Editing a record
  and recomputing the hashes -- which defeated v0.1 -- now fails verification when you verify with the recorder's
  public key (a ledger written without a signer still passes after the hashes are recomputed).
- **Anchors and witnesses.** The ledger head is published (signed) to a place you must arrange so that the
  operator cannot rewrite it alone; a verifier holding only that copy can then detect removal or editing of records
  up to the last anchor, provided the witness is independent of the operator.
- **Heartbeats.** The recorder periodically writes which tools it wraps, a hash of
  the policy in force, and how many calls it intercepted vs. recorded, so silent
  periods, tool/policy changes, and calls that ran without evidence show up.
- **Independent implementation of the verifier.** `verifier/` is a separate Rust program, written from the
  [public format spec](docs/spec/evidence-format-v2.md) and tested against the same
  conformance vectors as the Python code. One offline binary, no network. It was written by the
  same author as the Python code, so it checks that the two agree, not yet that the format is right.
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

## Stricter modes and behavior changes

```python
policy = PolicyEngine.from_yaml("policies/example_policy.yaml", strict=True)
guard = Guard(policy, ledger)           # a wrapped tool with no category is refused and recorded as `unclassified_tool`
replay = SqliteReplayGuard("replay.sqlite")   # one replay decision shared by every process on this host
```

- `strict` (or `strict_classification: true` in the policy): a tool with no category is refused. Without it, a warning
  is printed when such a tool is wrapped. Harmless tools say so with an explicit label such as `internal`.
- `state_change` is a category for actions that change an external system without necessarily communicating outward.
  With `enforce_state_change_after_untrusted: true` per agent, such a tool is refused once its workflow has read
  untrusted input, unless it is listed in `state_change_allowed_tools`.
- `SqliteReplayGuard` replaces the in-memory `ReplayGuard` when several agent processes on one host receive messages.
- `auditrail recorder` warns at startup about a missing or empty token. **Behavior change:** it now also *refuses to start*
  (exit code 2) when its signing key is readable by other accounts, its ledger/anchors are writable by them, or the
  permission check itself could not run (an unknown is treated as unsafe). Pass `--allow-loose-permissions` to get
  warnings (`NOT CHECKED` for the unchecked case) and start anyway. The Windows check reads the ACL for the broad
  groups only, so passing it is not proof the key is private.
- **Behavior change:** `internal` cannot be combined with another category on one tool. Such a policy fails to load
  (`PolicyError`, naming the tool and the categories), and so does a call-site label that contradicts the policy. Remove one
  of the two labels; there is no switch to allow the combination.
- **Behavior change:** a category must be a built-in name (`data_access`, `untrusted_input`, `external_comm`,
  `state_change`, `internal`, `agent_to_agent`) or be declared once under a top-level `custom_categories:` list in
  the policy (lower_snake_case). `State_Change`, ` internal`, `state-change` and typos raise `PolicyError` with the
  closest known name, in every mode. Declaring your own names is the way back; there is no switch that skips the
  check.
- **Behavior change:** the same tool labelled differently by two agent sections raises `PolicyError` when it is
  wrapped; give it one label set.
- **Behavior change (verifiers, Python and Rust):** two new statuses, `UNSUPPORTED_ALGORITHM` (inconclusive, exit 1: the trusted key is registered as an algorithm the verifier cannot check; a `.pub` file cannot express that, so file input gets `BAD_SIGNATURE` "algorithm mismatch" for any record that names an algorithm other than its Ed25519 key's) and `UNSUPPORTED_FORMAT` (`format` is an integer other than 2). An optional `sig_alg` member names the algorithm; absent means Ed25519 and Ed25519 is always written by omission, so existing ledgers are unchanged. An explicit `"sig_alg":"ed25519"` is rejected. See [the format spec](docs/spec/evidence-format-v2.md).

These make a *missing* label and an *unordered* write visible and refusable. They cannot tell that a label is wrong;
see "Opt-in hardening" in [SECURITY.md](SECURITY.md) for what each one does not cover.

## Evidence that can be checked without trusting the operator

This holds only if (1) the signing key is outside the agent's process and account (the recorder runs separately) and,
for the "without trusting the operator" claim, also out of the operator's reach after the fact -- for example on a host the operator
does not administer, or in hardware that signs on request (another OS account that the operator can administer does not
count) -- so the operator cannot later take the key and re-sign a rewritten history
(a key that signs on request from a KMS/TPM would also do, but that is not provided: you would write the signer
yourself); otherwise only an independent witness limits what the operator can rewrite; (2) the checker gets the
recorder's **public key by a route the operator cannot alter**; and (3) the witness copy is held somewhere the operator
cannot rewrite. Without those, see the limits in [SECURITY.md](SECURITY.md).

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
# 3. anyone, offline, with the recorder's public key (obtained by a route the operator cannot alter) and a witness copy.
#    auditrail-verify is the standalone Rust binary (build it or download it, see below):
auditrail-verify evidence.jsonl --pubkey keys/recorder.pub --witness witness-copy.jsonl --max-gap 120
#    the Python CLI does the same; note the flag is --witness-file there:
auditrail verify evidence.jsonl --pubkey keys/recorder.pub --witness-file witness-copy.jsonl --max-gap 120
```

`pip install` installs only the `auditrail` command. `auditrail-verify` comes from `cd verifier && cargo build --locked --release`
or from a release download.

The verifier prints `OK` only with a list of what it did **not** check (no key
given, no witness, no heartbeat limit, records after the last anchor).

### Getting the standalone verifier

`auditrail-verify` is a single static file written in Rust. **No release has been published yet**, so for now you build
it:

- Linux: `sudo apt install cargo` (or install Rust with rustup); Windows: install [rustup](https://rustup.rs/) and the
  Visual Studio C++ build tools it asks for; macOS: rustup.
- Then, from the repository root: `cd verifier && cargo build --locked --release`.
- The binary is `verifier/target/release/auditrail-verify` (`.exe` on Windows); check it with
  `verifier/target/release/auditrail-verify --version`.

Once a release exists (pushing a tag `v*` runs [`release.yml`](.github/workflows/release.yml), which builds it for
Linux x86_64, Windows x86_64 and macOS Apple silicon and Intel, runs the conformance vectors against each native
build, and publishes the files with a `SHA256SUMS` list and GitHub build-provenance attestations), the download steps
will be as below. **They do not work today, because `v0.2.0` does not exist.**

```bash
gh release download v0.2.0 --repo x91652-pixel/auditrail --pattern 'auditrail-verify-linux-x86_64' --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify auditrail-verify-linux-x86_64 --repo x91652-pixel/auditrail   # which workflow built it
chmod +x auditrail-verify-linux-x86_64 && ./auditrail-verify-linux-x86_64 --version
```

What this does and does not give you: the checksum and attestation say the file is the one this repository's
workflow built from a given commit. They do not say the repository itself is trustworthy, and a verifier you
downloaded from the same place as the evidence is only as independent as that place. For a high-stakes check,
build it from source at a commit you reviewed. Builds use `Cargo.lock` and fixed path/timestamp flags; two clean
builds on one machine were byte-identical, but identical bytes across different machines are not verified. The
Intel macOS binary is cross-compiled and is not executed in CI.

## Anchoring (protocol v1)

`verify` only proves the ledger is internally consistent: someone who rewrites
the whole ledger, or cuts off its tail, still passes it. Anchoring periodically
records the chain head (sequence number and hash, no tool arguments or results)
and publishes it to a witness outside the ledger owner's sole control. The full
current specification, including the signed (v2) anchors, is [docs/spec/evidence-format-v2.md](docs/spec/evidence-format-v2.md).

```bash
# record the current head; with --push, also push the witness commit
auditrail anchor --ledger ledger.jsonl --anchors anchors.jsonl --git-repo ../witness
auditrail verify ledger.jsonl --anchors anchors.jsonl --git-repo ../witness
```

`verify --anchors` reports one of `OK`, `TAMPERED_LEDGER`, `TAMPERED_ANCHOR`,
`UNSIGNED_ANCHOR`, `UNKNOWN_KEY`, `BAD_SIGNATURE`, `REWRITTEN`, `TRUNCATED`,
`SINK_MISMATCH`, or `SINK_UNREACHABLE`, plus how many records after the last anchor
are not covered. (`SINK_*` exist only in the Python verifier; the Rust one reads a
witness file and has no sinks. The full status list, including the record- and
heartbeat-level ones, is in the format spec.)

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

## A readable report

```bash
auditrail report evidence.jsonl --pubkey keys/recorder.pub --witness-file witness-copy.jsonl --max-gap 120 \
    --format all --out report          # writes report.md, report.html, report.json; exit 0 only if no check had a finding
```

The report says what the checks found, what they did **not** examine, and, in a section that cannot be switched
off, what no report of this kind proves. It is deterministic (same input, same bytes; add `--generated-at now` for a
timestamp), self-contained HTML, makes no network call, is not signed, and is a rendering of `verify`'s result, not
new evidence. `--redact` replaces the names of agents, tools and recorders by codes in the fields that carry them
(never the status words or the structure); the codes are **not secrets** (a guessable name can be recovered), so add
`--redact-salt SECRET` if that matters, and note that policy versions, timestamps, counts and input hashes are not
masked, nor is anything you put in `--title` or `--note`. Those two are printed on one line, escaped (a newline or
Markdown syntax in them cannot add a section or a link) and labelled as supplied and not examined. The first screen
says what ran and what did not from the outcomes, not from the flags (an empty witness file, an empty ledger or a
ledger reconciled against itself is named as such). Failures to write are a one-line error with exit 2; an existing
`--out` file is refused unless `--force`, and an input file is never overwritten. `stdout` is written as UTF-8 with
LF line ends, the same bytes as `--out`. Exit code 0 means the main ledger and every check you supplied (including peer ledgers) found nothing; 1 means any finding **or an inconclusive result**, which is not necessarily tampering (a problem with a peer ledger gives 1 while the main ledger's own status stays as it is, listed under `overall.secondary` in the JSON); 2 means an input file or the output could not be read or written, and no result is produced (the same for `verify` and `reconcile`: 0 no finding, 1 a finding or an inconclusive result, 2 an input file could not be read, for example a malformed `--pubkey` file). A `--redact-salt` is passed on the command line, so it is visible in the process list and shell history.

To see the whole path in one go (an agent, a signature, a witness copy, one record altered, the verifier catching it,
two reports), on Windows or Linux:

```bash
python -m examples.mvp_demo.run
```

In that demonstration the agent and the key are on one machine, so it shows the mechanism, not a deployment.

### Reading a report

A report is easy to over-read. The numbered points below are what it does not say; the full, fixed list is in its last section.

1. **"No inconsistency found" is not "safe".** It means the checks that ran, over the records they covered, found nothing; the report lists what ran and what did not.
2. **It covers only the tools the recorder wrapped.** An action by a tool that was not wrapped leaves no record, and the report cannot see it.
3. **An unreadable or empty input is not a clean one.** An empty ledger, an empty witness file or a v0.1 ledger is reported as not examined, never as consistent. An empty ledger still exits 0 with status `OK`, and the report text says nothing was examined; an unreadable input exits 2 and no report is written.
4. **Without a key, a consistent chain proves little.** Anyone who could write the file could have rewritten it consistently; check signatures with a key you trust.
5. **Without an independent witness copy, removal or rewriting of records is not detectable**, and records after the last anchor are not covered by it.
6. **A witness is only as independent as the people who hold it.** If the operator controls the witness copy, it adds little.
7. **"Trusted" key means supplied, not verified.** The tool does not check where a key file came from.
8. **A matched message pair shows two records agree, not that the other side is independent.** The same signing key on both sides is a clue that it is not; a different key does not prove that it is.
9. **Exit code 1 is a finding or an inconclusive result, not necessarily tampering.** `UNSUPPORTED_*` can be provoked by editing a field and never means "untouched".
10. **The report is not signed and can be edited**; its fingerprint helps compare two copies, it does not vouch for the content.
11. **`--redact` is masking, not anonymisation.** The codes are not secrets, several fields stay visible, and the title and note are never masked.
12. **The report was produced from the files you gave it.** If the recorder's host or key was compromised, none of it holds.
13. **Heartbeats show only that the gap limit was checked.** They do not show that the agent used no tool that was not wrapped.
14. **A `.md` file read as plain text shows escaping backslashes**; the rendered Markdown and the HTML do not.
15. **The first screen is not the whole report.** The complete list of limits is in section 10; do not rely on the Result section alone.
16. **`SECURITY.md` is not shipped with the package.** The report records only the hash of the file its list of limits was generated from, not which commit it came from.
17. **"Verifier's original wording" is the verifier's text, not a promise by the report.** A phrase such as "all signatures valid" there describes what that check examined, under the limits above.

## Quickstart

Python 3.10 or newer is what CI tests (`pyproject.toml` allows 3.9, untested). Work in a virtual environment (a folder of
Python packages kept just for this project): on recent Debian-based distributions (we saw it on
Ubuntu 26.04) pip can refuse a system-wide install with "externally-managed-environment"
([PEP 668](https://peps.python.org/pep-0668/)); this is from our own test run, not a statement about every Ubuntu version.

```bash
# Linux / macOS (on Ubuntu first: sudo apt install git python3-venv python3-pip)
git clone https://github.com/x91652-pixel/auditrail
cd auditrail
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # just to try it; use  pip install -e ".[dev]"  only if you want to run the tests
```

```powershell
# Windows PowerShell -- no activation needed, so the execution policy does not matter
git clone https://github.com/x91652-pixel/auditrail
cd auditrail
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
# then run everything below as  .venv\Scripts\python.exe -m ...  and  .venv\Scripts\python.exe -m auditrail.cli ...
# (activating with .venv\Scripts\Activate.ps1 may be blocked by your PowerShell execution policy -- on a Windows client
#  with no policy set, scripts are usually blocked; if you want to activate, run
#  Set-ExecutionPolicy -Scope Process Bypass  in that window only)
```

Below, `python` means the virtual environment's Python (after activating it, `python` works on Linux too; without
activating, use `.venv/bin/python` and `.venv/bin/auditrail`; on Windows `.venv\Scripts\python.exe` and
`.venv\Scripts\auditrail.exe`; a system `python3` does not see the packages) and `auditrail` is the command `pip install`
created in it.

Two demos, which write to different places:

```bash
# 1. the repository's example: writes examples/demo_ledger.jsonl
python -m examples.mock_demo
auditrail verify examples/demo_ledger.jsonl

# 2. the installed command: writes to your temporary directory; the last line of its output names the file
auditrail demo
auditrail verify <the path printed on that last line>
```

Windows without activating (same two demos):

```powershell
.venv\Scripts\python.exe -m examples.mock_demo
.venv\Scripts\auditrail.exe verify examples\demo_ledger.jsonl
.venv\Scripts\auditrail.exe demo
.venv\Scripts\auditrail.exe verify <the path printed on that last line>
```

Both run on your machine with no API key. **Each makes one real HTTP request** (to `https://api.github.com/zen`, with
a 3 second timeout) to exercise an external-communication tool; if you are offline that step is skipped and
everything else still runs. They exercise an allowed pipeline, a trifecta block, a signed agent message (and a
rejected forged or replayed one), and tamper detection.

The demos write an unsigned ledger (`*.jsonl` is git-ignored, so the file exists only after you run the demo).
`verify` therefore reports what it did **not** check: signatures, anchors and heartbeats.

Wrap a tool function (run from any directory once the package is installed; this is the whole file):

```python
from auditrail import Guard, Ledger, PolicyEngine

# a minimal policy, inline so nothing else is needed
POLICY = {
    "version": "quickstart",
    "agents": {"hr-screener": {"allowed_tools": ["read_resume"],
                               "tool_categories": {"read_resume": ["data_access"]}}},
    "default": {"allowed_tools": [], "enforce_lethal_trifecta": True},
}
guard = Guard(PolicyEngine(POLICY), Ledger("evidence.jsonl"))   # no signer: hash-chained, not signed

@guard.guarded_tool("read_resume", categories=["data_access"])
def read_resume(candidate_id: str) -> dict:
    return {"candidate": candidate_id, "years_experience": 7}   # stand-in for your real function

session = guard.session(agent_id="hr-screener")
print(read_resume(session, "cand-001"))        # policy-checked and logged
```

Then `auditrail verify evidence.jsonl` (`.venv\Scripts\auditrail.exe verify evidence.jsonl` on Windows without
activating). See [`examples/mock_demo.py`](examples/mock_demo.py) for the full walkthrough
(including the trifecta-block and tamper-detection scenarios), [`policies/example_policy.yaml`](policies/example_policy.yaml)
for a policy file, and [`examples/real_agent_demo.py`](examples/real_agent_demo.py) for a live example with Claude
doing real tool-use (`ANTHROPIC_API_KEY` required).

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full data-flow
diagram and the reasoning behind two specific design choices: why the
policy engine reasons about tool *categories* rather than tool identities,
and why the ledger stores argument/result digests rather than raw payloads.

## Where this fits

auditrail is a runtime primitive, not a platform. The analogy is the change logs infrastructure teams keep
-- a boring, verifiable record -- applied to wrapped agent tool calls (an analogy, not a compliance claim). It's deliberately
narrow and meant to compose with things that already exist:

| If you need... | Consider |
|---|---|
| Prompt-injection / jailbreak detection on inputs and outputs | A prompt-injection / jailbreak detection product |
| Agent discovery, fleet-wide policy across SaaS platforms | An agent governance platform |
| A certifiable standard for an agent | [AIUC-1](https://www.aiuc-1.com/), a standard for AI agents with third-party certification (per its own pages: accredited auditors and annual re-certification) |
| An org-wide AI risk/compliance workflow | An AI governance / risk-management software product |
| **A tamper-evident record of the wrapped tool calls in one agent session, that you own and can verify yourself, in your own code, with no vendor lock-in** | **auditrail** |

## Status

v0.2 -- early, unreleased on PyPI, as far as we know not yet used in production, no
independent security review. The format is a draft: expect changes until a second
team has implemented it. Issues, and especially "this
broke when I tried it against a real agent" reports, are exactly what
this stage needs. See [ROADMAP.md](ROADMAP.md).

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

All 802 Python tests (a few run only on POSIX and several only on Windows, the others everywhere) are deterministic and require no network access or API key
(one demo scenario attempts a single real HTTP call and skips gracefully
if you're offline). The Rust parts have their own tests: `cd verifier && cargo test`
(runs every [conformance vector](docs/spec/vectors) through the independent verifier) and
`cd dashboard && cargo test`. Python tests that compare against the Rust verifier are
skipped until you run `cd verifier && cargo build --locked --release`.

The two verifiers are also fuzzed against each other (`tests/test_fuzz.py`, Hypothesis; raise the sample size with
`AUDITRAIL_FUZZ_EXAMPLES=500`): random ledgers, field edits, raw byte corruption, re-hash attacks, truncation and garbage
must give the same status in Python and Rust, and never a crash. `tests/test_reader_agreement.py` pins down the odd
inputs (non-UTF-8, `-0`, `true` as an integer, signatures with a space, ...) one by one.

To see the attack simulation (a fictional logistics company with five
agents, 11 normal operations and 19 attack scenarios: 15 defended, of which #17 and #18 hold only with the opt-in strict / `state_change` settings, and 4 documented gaps (#3, #11, #13, #19)):

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
