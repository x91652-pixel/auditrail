# `auditrail report` and the MVP demo

Status: **design proposal, not implemented.** Nothing in `src/`, `verifier/`, `tests/`, `docs/spec/` or the
vectors changes with this document. Baseline: `hardening-fixes@0bc245b`.

Goal (user option B): the demo ends in **a document a person who is not an engineer can read**, and that document
is as careful about what it did *not* check as the verifier is.

---

## 1. The `auditrail report` command

### 1.1 Interface

```
auditrail report LEDGER
    [--pubkey FILE]...            trusted recorder public key(s), as for `verify`
    [--anchors FILE]              the owner's anchors file
    [--witness-file FILE | --git-repo DIR]   a witness copy of the anchors
    [--max-gap SECONDS]           heartbeat gap limit (as for `verify`)
    [--peer-ledger FILE]...       other parties' ledgers, for the agent-to-agent section
    [--agent ID]...               agent ids whose ledgers are among those given (as for `reconcile`)
    [--format md|html|json|all]   default: md
    [--out PATH]                  file, or a directory when --format all; `-` writes to stdout (md/json)
    [--title TEXT] [--note TEXT]  optional, rendered escaped and labelled as unverified
    [--generated-at now|ISO8601]  stamp the report; absent means no timestamp at all
    [--redact]                    replace agent/tool names by stable short digests
```

Exit code mirrors `verify`: **0** the report was written and every check that was asked for found no
inconsistency; **1** the report was written and some check failed or was inconclusive; **2** an input could not be
read (no report is written, because a report about unreadable evidence would only be a guess).

The command **never touches the network and never calls an LLM**; it is a pure function of its input files, the
`auditrail` version and the flags.

### 1.2 Determinism

- Same input bytes + same `auditrail` version + same flags ⇒ **identical output bytes**. No locale, no wall clock,
  no environment, no dict-order dependence (all lists sorted by an explicit key), `\n` line endings, UTF-8.
- The only varying line is the optional `Generated:` stamp. It is **off by default**; `--generated-at now` or an
  explicit ISO time adds it. The report's **fingerprint** (SHA-256 of the body excluding that one line) is printed
  separately, so two stamped reports of the same evidence still show the same fingerprint.
- Each input file's SHA-256 is printed ("what exactly was examined"), including the public keys.
- HTML is self-contained: inline CSS, no JavaScript, no external fonts/images/links that load.

### 1.3 Why it cannot just call `verify_all`

`verify_all` follows the spec: it runs checks in order and **stops at the first failure**, returning one status.
That is right for a verifier and wrong for a report: after `HEARTBEAT_GAP` a reader still wants to know the anchor
result and the policy timeline. The report therefore needs a "collect everything that can still be evaluated"
function (new, in a new module) that calls the existing pieces separately:

- if the chain or a signature fails (`TAMPERED_LEDGER`, `UNSIGNED_RECORD`, `UNKNOWN_KEY`, `BAD_SIGNATURE`,
  `MALFORMED_RECORD`), every later section is shown as **"not evaluated: the records cannot be relied on"**, with
  the verified prefix (`seq` 0..`bad_seq`-1) stated; nothing computed from the unreliable part is presented as fact;
- otherwise anchors, witness, heartbeats and A2A are each evaluated and reported independently.

### 1.4 Sections and where each one's data comes from

| # | section | content | already available from | to be added |
|---|---|---|---|---|
| 0 | **Result** | one sentence with the overall status, and the list of checks that ran / did not run | `verify_all` fields `status`, `notes`; `cmd_verify` exit logic | collected-status composition (1.3) |
| 1 | **What was examined** | file names (as given), SHA-256 of each input, auditrail version, record count, `seq` range, first/last `ts`, counts per `kind` | `verify_all`: `records`, `kinds`; records' `seq`, `ts` | file hashing; first/last `ts` (trivial) |
| 2 | **Keys** | each trusted key: `key_id` and the **full** SHA-256 of the raw public key, signature algorithm (`ed25519`; reserved for D-11), and whether every record was signed by one of them | `keys.load_public_keys`, `key_id_for`; `signatures_checked`; `UNSIGNED_RECORD`/`UNKNOWN_KEY` | full-key fingerprint helper |
| 3 | **Verification outcome** | for each check: ran / did not run / result, with a plain-language explanation of the status code (1.5) | `verify_all`, `verify_anchors`, `verify_witness_file`, `check_chain`, `check_heartbeats` | the explanation table; per-check collection (1.3) |
| 4 | **Witness** | which copies were given (`file`/`git`), the highest anchored `seq`, whether the witness copy alone is enough to expose a rewrite, `SINK_UNREACHABLE`/`SINK_MISMATCH` handling, and "no witness given" stated plainly | `verify_anchors` (`anchored_upto`, `unanchored_tail`, `sink_ref`), `verify_witness_file` | present per-anchor table (seq, created_at, key_id, sink_ref) |
| 5 | **Unanchored tail** | the range of records after the last anchor, by `seq` and time, and that nothing about them is covered | `verify_all`: `anchored_upto`, `unanchored_tail` | convert to a `seq`/time range |
| 6 | **Heartbeats** | recorder ids seen, interval, gaps longer than the limit (from/to/seconds), counts `calls_attempted` vs `calls_recorded`, and "no limit was given" when none | `check_heartbeats` (gaps only inside a failure today), `verify_all` `changes` | **a non-failing gap computation** (small refactor of `check_heartbeats`) |
| 7 | **Policy and tools over time** | each distinct `policy_hash` with `policy_version` and the `seq`/time range it was in force; the points where the wrapped-tool list changed (added/removed) | `verify_all`: `policy_hashes`, `changes` (needs `--max-gap` today) | compute `changes` without requiring `--max-gap`; timestamps for `first_seq` |
| 8 | **Refusals** | counts of `deny`, `error`, `sandboxed`, grouped by reason class (`lethal_trifecta`, `unclassified_tool`, `state_change_after_untrusted`, `label_conflict`, not allow-listed, other) and by tool and agent | the records' `decision`, `reason`, `tool`, `agent_id` | the grouping (classify `reason` by its leading token; unknown reasons go to "other", never dropped) |
| 9 | **Agent-to-agent** | messages recorded by both sides, one-sided messages (`SEND_WITHOUT_RECV`, `RECV_WITHOUT_SEND`, `ACK_WITHOUT_RECV`), rejected messages, how many involve ledgers that were not supplied | `reconcile.reconcile` (`matched`, `findings`, `rejected`, `unverifiable`) | only wiring; section omitted (and said to be omitted) when no peer ledgers are given |
| 10 | **What this report does not prove** | fixed text; see 2 | — | the generator and its lock (2) |
| 11 | **Optional title/note** | printed at the top, labelled "supplied by whoever generated this report, not examined" | — | flag handling and escaping |

### 1.5 Plain-language explanations (one table, covered by a test)

Every status string the verifiers can emit has an entry in a single table that holds: the short label, one sentence
of what it means, one sentence of what it does **not** mean, and whether it is evidence of tampering, an
inconclusive result, or a note. Entries (existing statuses; new ones are *reserved* as described in 5.3):

| status | class | what the report says (gist) |
|---|---|---|
| `OK` | consistent | "The checks that were run found no inconsistency. See 'not checked' and 'does not prove'." Never "verified", never "safe". |
| `TAMPERED_LEDGER` | tamper evidence | records at and after `seq` N do not match their own hashes or links; records before N are consistent. |
| `UNSIGNED_RECORD`, `UNKNOWN_KEY`, `BAD_SIGNATURE` | tamper evidence / key problem | signatures were required; a record has none, names a key that was not given, or fails verification. For `UNKNOWN_KEY`: "this may simply be the wrong key file". |
| `MALFORMED_RECORD` | malformed | the record is internally consistent but breaks the format's field rules. |
| `TAMPERED_ANCHOR`, `UNSIGNED_ANCHOR` | tamper evidence | the anchors file or witness copy was altered, or lacks the signature that was required. |
| `TRUNCATED` | tamper evidence | the witness holds an anchor for a record the ledger no longer has. |
| `REWRITTEN` | tamper evidence | a record the witness vouches for was changed. |
| `SINK_MISMATCH` | tamper evidence | the witness does not contain an anchor the owner's file claims was published. |
| `SINK_UNREACHABLE` | **inconclusive** | a witness could not be read; the anchor was **not** checked (this is not evidence of tampering). |
| `NO_HEARTBEAT`, `HEARTBEAT_GAP`, `UNRECORDED_CALLS` | completeness finding | silent period(s); or the recorder counted calls it intercepted but did not record. |
| `LEGACY_FORMAT` | **inconclusive** | an old (v0.1) ledger: unsigned and not covered by these checks; `--legacy-v01` gives only a hash-chain check. |
| `UNSUPPORTED_ALGORITHM`, `UNSUPPORTED_FORMAT` *(reserved, D-11)* | **inconclusive** | the report generator cannot check this input; not tampering. |
| any status not in the table | **inconclusive** | printed verbatim with "this report version has no explanation for it"; never treated as OK. |
| *(not a status)* signatures not checked / no witness / no heartbeat limit | **not checked** | each listed under "Not checked", not hidden in a footnote. |

A test enumerates the status strings found in `verifier.py`, `anchor.py`, `reconcile.py` (and later `lib.rs`) and
fails if any is missing from the table.

---

## 2. The fixed section "What this report does not prove"

It cannot be switched off: there is no flag for it, it appears in every format, and a test runs the command with
every flag combination and asserts the heading is present.

### 2.1 Where the text comes from

The authoritative list is `SECURITY.md`, section "What v0.2 does NOT do" (the bold-led bullets under *About the
evidence*, *About the policy and messages*, *About isolation*, *About scope*), plus "Where the tests do not reach".
`SECURITY.md` is **not part of the installed package**, so the report cannot read it at run time. The design:

1. `tools/gen_limits.py` parses `SECURITY.md` and writes `src/auditrail/_limits.py`: a tuple of items, each the
   **bold lead sentence** of a bullet (e.g. "Records after the last anchor are not covered."), its group heading,
   and the SHA-256 of the `SECURITY.md` text it came from.
2. The report embeds the bold lead sentences verbatim and prints "Source: SECURITY.md (sha256:…)" and a pointer to
   read the full text. It does not embed whole paragraphs (they are long and carry conditions that deserve the full
   document).
3. A repository test regenerates the file in memory and asserts it equals the committed `_limits.py` (the same
   pattern as `generate.py` + `git diff --exit-code` for the vectors). Editing `SECURITY.md` without regenerating
   fails CI, so the report cannot silently show stale limits.

### 2.2 Making a format change loud

- The parser is strict: it requires the exact headings above and bullets that begin with `- **`; zero items from any
  group, or fewer items than a recorded minimum, **fails the generator** (and its test) instead of producing an empty
  section.
- A small **floor** is hard-coded in the report module and always printed even if the generated list were empty:
  1. only wrapped tools are seen, and an unwrapped tool leaves no trace;
  2. records after the last anchor are not covered;
  3. nothing is established if the recorder host or its key was compromised;
  4. a witness that colludes with the operator defeats the anchors;
  5. the report examines evidence; it does not judge whether recorded actions were appropriate.
  A test asserts each floor sentence appears in `md`, `html` and `json`.
- The generated items and the floor are de-duplicated by exact sentence; the order is the document's order.

---

## 3. Honesty rules

### 3.1 Vocabulary

The report's own sentences never use the words *safe, secure, compliant, compliance, certified, audited, approved,
passed, guarantee(d)*, or their Chinese equivalents if a zh rendering is added (安全, 合規, 通過稽核, 保證). A test
renders a spread of fixtures (OK, every failing status, no keys, no witness, legacy) and scans **everything outside
the generated limits section** against a case-insensitive whole-word list. The limits section is excluded
because `SECURITY.md` itself says "Not a certified compliance product"; those occurrences are negations in quoted
text and are labelled as quotations. (*Decision 6.*)

The positive result is phrased as: **"The checks listed under 'Checks that ran' found no inconsistency."**

### 3.2 Environment limits

The report is about a ledger. It cannot know how the recorder host was configured, so it says that instead of
implying it:

- "Whether the recorder's key file, ledger and anchors were protected from other accounts is **not recorded in the
  ledger and not examined by this report**." The recorder's start-up permission check (and its `NOT CHECKED` outcome,
  e.g. PowerShell unavailable) is a property of the recorder process, printed on its console; it is **not** in the
  evidence. (Possible later extension: a `recorder_start` event kind. Not proposed here.)
- Likewise: clock source, operating-system separation between agent and recorder, whether the key was ever copied.
- Anything the verifier could not check is under **Not checked**, with the literal words "NOT CHECKED" when that is
  what the verifier said.

### 3.3 "Only wrapped tools"

A fixed paragraph in the Result and again in the heartbeat section: *"This report covers only tool calls that went
through the recorder's wrapped tools. The tool list shown under 'Heartbeats' is what the recorder reports as wrapped,
not a statement of what the agent can do. An action by a tool that was not wrapped leaves no record, and this report
cannot see it."* When no heartbeat exists, the sentence is followed by "No heartbeat was recorded, so even the list
of wrapped tools is unknown."

---

## 4. The MVP demonstration

### 4.1 What it must show, in order

simulated agent calls tools → recorder signs → anchor published to a witness outside the operator's files →
**one record deliberately altered** → verifier catches it → a report is produced.

### 4.2 Command sequence (identical on Windows and Linux)

No shell-specific syntax: every step is a `python`/`auditrail` invocation, paths use `/`, and the tampering step is a
Python script, not `sed`/`PowerShell`.

| # | step | command | expected output (summary) |
|---|---|---|---|
| 0 | install | `pip install -e ".[dev]"` | installs; `auditrail --help` works |
| 1 | recorder key | `auditrail keygen --out demo/recorder` | `demo/recorder.key`, `demo/recorder.pub` created |
| 2 | simulated agent | `python examples/mvp_demo/agent.py --key demo/recorder.key --out demo/ledger.jsonl` | prints each call: 3–4 allowed, 1 **refused** (`lethal_trifecta`), 1 refused (`unclassified_tool`, strict); writes a signed ledger with heartbeats |
| 3 | publish anchor | `auditrail anchor --ledger demo/ledger.jsonl --anchors demo/anchors.jsonl --key demo/recorder.key --witness-file demo/witness.jsonl` | `[ANCHORED] … sink_ref=file:…` (the witness copy stands in for "somewhere the operator cannot rewrite") |
| 4 | verify the original | `auditrail verify demo/ledger.jsonl --pubkey demo/recorder.pub --anchors demo/anchors.jsonl --witness-file demo/witness.jsonl --max-gap 120` | `[OK] … records, hash chain intact`, `all records signed by a trusted key`, `anchored up to seq=N (0 record(s) after it not covered)`; exit 0 |
| 5 | alter one record | `python examples/mvp_demo/tamper.py demo/ledger.jsonl demo/ledger-tampered.jsonl` | prints which `seq` was changed (`deny` → `allow`) |
| 6 | verify the altered copy | same as 4 with `demo/ledger-tampered.jsonl` | `[TAMPER DETECTED] … chain breaks at seq=K`; exit 1 |
| 6b | the cleverer attempt (optional) | `python examples/mvp_demo/tamper.py --rehash …` then verify | the chain is internally consistent again, but `BAD_SIGNATURE` at seq K; and `REWRITTEN`/`TRUNCATED` via the witness copy |
| 7 | report on the altered copy | `auditrail report demo/ledger-tampered.jsonl --pubkey demo/recorder.pub --witness-file demo/witness.jsonl --max-gap 120 --format all --out demo/report-tampered` | writes `.md`, `.html`, `.json`; exit 1 |
| 8 | report on the original | same with `demo/ledger.jsonl` and `--out demo/report` | exit 0; section "Result" says the checks found no inconsistency, with "does not prove" |

One-shot form: `python -m examples.mvp_demo.run` runs steps 1–8 in a temporary directory, prints each step's
one-line outcome and returns 0 only if every expectation held (the same pattern as
`python -m examples.logistics_sim.run`). It is also the natural body of a CI job on both operating systems, which is
what would make "works on a clean clone, Windows and Linux" a checked fact instead of a claim.

### 4.3 What can be reused

| existing | reuse |
|---|---|
| `auditrail keygen`, `anchor`, `verify` (all flags) | steps 1, 3, 4, 6 as they are |
| `examples/logistics_sim/` | its `company.POLICY` / `STRICT_POLICY` and tools are a ready, realistic cast; `run_simulation` already produces a signed ledger, anchors and a witness — but writes no `.pub`, so the MVP script uses its own small agent over the same policy rather than coupling to the simulation |
| `auditrail demo` (`_demo.py`) | the narrative (allow → deny → trifecta → tamper) is the right shape; it is unsigned and unanchored, so it is a precedent, not a component |
| `examples/mock_demo.py` | scenario text |
| the tamper helpers in `run_simulation` (`ledger_tamper`, `signed_rewrite`, `witnessed_truncation`) | they are nested functions; the logic is ~15 lines each and would be re-implemented in `tamper.py` |
| `dashboard/` (Rust) | an existing local web UI over the same data (`/api/verify`, `/anchoring`); not needed for the demo, and the report must not depend on it |

### 4.4 What the demo must say about itself

The agent and the recorder key live in one directory on one machine in the demo. The script prints, before step 2,
that this is a demonstration of the *mechanism*: in a real deployment the recorder runs as a separate process or
account (`auditrail recorder`), and the witness is somewhere else. The report's section 10 says the same in general
terms.

---

## 5. Implementation scope

### 5.1 Files

| new / changed | file | note |
|---|---|---|
| new | `src/auditrail/report.py` | collect + render (md, html, json); no I/O beyond reading inputs and writing outputs |
| new, generated | `src/auditrail/_limits.py` | from `SECURITY.md`; checked in |
| new | `tools/gen_limits.py` | the generator, also run by its test |
| changed | `src/auditrail/cli.py` | `report` subcommand and flags |
| changed (refactor, no behaviour change) | `src/auditrail/verifier.py` | expose `check_heartbeats`' gap computation and the policy-timeline loop as helpers |
| new | `examples/mvp_demo/{agent.py,tamper.py,run.py}` | the demo |
| new | `tests/test_report.py`, `tests/test_report_limits.py`, `tests/test_mvp_demo.py` | |
| changed | `README.md`, `SECURITY.md`, `docs/STATUS.md` | document the command and its limits |

No change to `verifier/` (Rust): the report is a Python feature built on the Python verifier; the Rust binary keeps
its own plain output. No change to the evidence format or the vectors.

### 5.2 Test increment (estimate: 45–60)

- determinism: same input twice → identical bytes; flags that must not change bytes; fingerprint stable under
  `--generated-at` (4–5);
- every status → explanation entry; unknown status → "inconclusive", never OK (3);
- sections present/absent for each input combination; "not evaluated" after a chain failure (8–10);
- refusal grouping including `unclassified_tool`, `label_conflict`, `state_change_after_untrusted` (3–4);
- limits: regeneration equals committed file, strict-parse failure on a mutated `SECURITY.md`, floor present in all
  three formats, heading present under every flag combination (6–8);
- vocabulary scan across fixtures (2–3); HTML escaping of `--title`/`--note`/names (3); `--redact` (3);
- A2A section with matched / one-sided / rejected / unsupplied ledgers (4);
- demo: `examples.mvp_demo.run` returns 0 and produces the expected statuses (3–4).

### 5.3 Compatibility with D-11 (reserved, not implemented)

The explanation table is keyed by status string with a fallback, so `UNSUPPORTED_ALGORITHM` and
`UNSUPPORTED_FORMAT` only need table entries when they exist (they are already listed above as reserved). The Keys
section prints the algorithm per key from the verifier's registry; today it is always `ed25519`, and a record's
`sig_alg` (if D-11 is adopted) is shown in the examined-records summary. If a record's algorithm is unsupported the
report says the signature check was **inconclusive** for those records, in the Result and under "Not checked". No
part of the report format depends on D-11 being accepted.

### 5.4 Risks

- Presentation drifting from the verifier's meaning → mitigated by the single explanation table and the status
  enumeration test.
- A pleasant document inviting over-trust → mitigated by the fixed section, the vocabulary scan and the "does not
  prove" floor; still a real risk, which is why the *Result* sentence is written as "found no inconsistency".
- Scope growth (regulation mappings, scoring, charts) → section 7.

---

## 6. Decisions needed from a person (with a recommendation)

| # | question | recommendation |
|---|---|---|
| 1 | HTML self-contained (inline CSS, no JS, no external resources)? | **Yes.** It can be emailed or opened offline, and nothing in it can phone home. |
| 2 | Also emit JSON (`--format json`)? | **Yes**, same data as the document, stable key order; it is what an auditor's tooling would consume and what tests assert against. |
| 3 | Custom title/note? | **Yes**, both optional, escaped, and labelled "supplied by whoever generated this report; not examined"; they cannot alter or hide any section. |
| 4 | Mask agent/tool names when sharing? | **`--redact`, off by default**: names become stable short digests (same name → same token within a report); the report says it is redacted and that the digests are not secrets. Arguments and results are already digests-only. |
| 5 | Timestamp on the report? | **Off by default** (byte-identical output); `--generated-at` to add it. |
| 6 | Banned-word scan: exclude the quoted limits section? | **Yes**, exclude it, because the quoted text legitimately says "not a certified compliance product". Alternative: rewrite the sentence in `SECURITY.md` to avoid the words. |
| 7 | Sign the report? | **No.** It is a rendering of evidence, not evidence; signing would make people trust the document instead of re-running the verifier. State the input hashes and the command instead. |
| 8 | Demo agent in-process (no `auditrail recorder` process) for v1? | **Yes for the one-shot script** (simplest, same on both OSes); add the real recorder process as a documented variant, since its Linux shutdown path has not been run by us. |
| 9 | Language? | **English first**, all strings in one table so a Chinese rendering is a table, not a rewrite. |
| 10 | Large ledgers | Provide `--max-rows` for list sections (counts always complete); default generous. |
| 11 | Should the recorder write a start-up event (permissions result, version) so a report can state it? | **Not now**; it changes the evidence format. Revisit with D-11. |

---

## 7. What this does **not** do

- No regulatory mapping (EU AI Act fields, NYC LL144, ISO/IEC 42001, AIUC-1): a separate piece of work, and a
  mapping is exactly the place where "compliant" language creeps in.
- No charts, graphs or other visualisation; tables and text only.
- No score, grade, traffic light, risk rating or recommendation of what to do.
- No judgement about whether any recorded action was appropriate or safe.
- No network access, no LLM, no hosted service, no telemetry.
- No signing, encryption or retention of the report; no replacement for running `verify` and keeping the witness copy.
- No new evidence: the report reads what the ledger, anchors, witness and peer ledgers already contain.
- No change to the evidence format, the verifiers' behaviour, or any status code.
