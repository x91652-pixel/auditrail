# D-11: optional algorithm and format identifiers

Status: **decided (D-12, all eight "as recommended") and implemented on branch `d11-sig-alg`.** The sections below
are the design as proposed; section 6 now records the decisions. Two points were settled while implementing:
`UNSUPPORTED_FORMAT` is evaluated *after* the record's hash holds (tamper evidence outranks "cannot read"), and
the grammar token is checked with a whole-string match (the N-1 lesson).
Decision recorded by the user: reserve an *optional* signature-algorithm identifier and a format identifier in the
evidence format, with an absent field meaning Ed25519. No ES256, no interoperability with the IETF AAT draft.

The short version:

- one new optional field, `sig_alg`, on records and (as `anchor_version` 3) on anchors;
- **absent means `ed25519`, and an Ed25519 writer must keep omitting it**, so every existing ledger, anchor and
  all 15 conformance vectors stay byte-for-byte what they are today;
- only the *signature* algorithm becomes agile; SHA-256, the canonical form and the chain stay fixed;
- two new, non-tamper statuses so a verifier says "I cannot check this" instead of "tampered" or "ok".

---

## 1. The fields

### 1.1 What exists today

| identifier | where | type | meaning |
|---|---|---|---|
| `format` | every record | int, `2` | structural version of a record. Its absence is how a v0.1 ledger is recognised (`LEGACY_FORMAT`). **Readers do not currently check its value** (only its presence). |
| `anchor_version` | every anchor line | int, `1` or `2` | `1` unsigned, `2` signed with `key_id` in the body. Unknown values are `TAMPERED_ANCHOR` ("unsupported anchor_version"). |
| `key_id` | signed records, v2 anchors, A2A envelopes | 16 hex | first 16 hex of `SHA-256(raw 32-byte public key)`. Names a key; says nothing about its type. |
| `v` | A2A envelopes | int, `2` | envelope version. Out of scope here. |

There is no algorithm identifier anywhere: Ed25519 is implied by the domain tags, by the 128-hex signature length
check and by the 64-hex key file rule.

### 1.2 What is added

| field | name | where | type | omittable | when omitted |
|---|---|---|---|---|---|
| signature algorithm | **`sig_alg`** | signed records; anchor lines of `anchor_version` 3 | string, lower case, `[a-z0-9-]{1,32}` | yes | `ed25519` |
| format check | *(no new field)* | records | the existing `format` | — | see 1.4 |

Rules:

1. **Canonical form is omission.** A writer using Ed25519 MUST NOT write `sig_alg`. A reader that meets
   `"sig_alg":"ed25519"` answers `MALFORMED_RECORD` (records) or `TAMPERED_ANCHOR` (anchors). Two spellings of one
   meaning would be a second encoding for the reader-agreement tests to police, and buys nothing.
   (*Decision 1 in section 6 if you prefer "accept".*)
2. `sig_alg` is a registry token. Today the registry has exactly one entry, `ed25519`, which is the implied one.
   Nothing else is defined, reserved by name, or implemented (section 7).
3. Where it lives:
   - **Records**: a top-level member next to `key_id`, e.g.
     `{"format":2,"seq":0,…,"key_id":"…","sig_alg":"<token>","prev_hash":"…","hash":"…","sig":"…"}`.
   - **Anchors**: `anchor_version` **3** carries `sig_alg` *inside the hashed body* (next to `key_id`) and is used
     **only** when the algorithm is not Ed25519. Ed25519 anchors stay `anchor_version` 2. A version-3 line without
     `sig_alg`, or version 2 with one, is `TAMPERED_ANCHOR`.
   - **Witness files** hold anchor lines, so they follow the anchor rule. There is no separate witness format.
   - **Key files** (`.pub`): unchanged for Ed25519 (exactly 64 hex digits, R-2). A key of another algorithm will need
     an explicit, different file form; that form is *not* designed here (Decision 5), because it depends on the
     algorithm that motivates it. The strict rule already rejects any prefix, so an old reader fails closed on it.

### 1.3 Hash algorithm: not included, and why

`sig_alg` covers signatures only. SHA-256 is used for `hash`, `anchor_hash`, `key_id`, `args_digest`,
`result_digest`, `policy_hash`, `msg_digest`, the 64-zero genesis `prev_hash`, and every "64 lowercase hex" length
rule in both verifiers and the fuzzers. A second hash would touch all of them at once, would change the hash of
every record, and is not a field you can make optional. If SHA-256 is ever replaced it is a **new major `format`**
(3), written and read as a different format, not a flag. The AAT draft also fixes SHA-256, so nothing is lost for
the user's stated goal.

### 1.4 `format`

The spec says `format` is `2`, but neither reader looks at the value. A future structural change that bumps it would
be silently misread by a v2 reader (the chain may even verify). The design therefore proposes a small tightening that
costs nothing for any ledger a current writer produced (all carry `2`):

- `format` present and an integer other than `2` → new status **`UNSUPPORTED_FORMAT`** (section 3).
- `format` absent → `LEGACY_FORMAT`, unchanged.

(*Decision 3.*) No other format identifier is introduced: the file has no header, and a per-record `format` plus
`anchor_version` already identify what each line is.

### 1.5 Relationship to `key_id`

`key_id` still names *a key*; `sig_alg` says *how the key signs*. A verifier resolves `(key_id) → (algorithm, key)`
from its trusted keys and then compares that algorithm with the record's `sig_alg` (absent = `ed25519`). For Ed25519
nothing changes: `key_id = SHA-256(raw public key)[:16]`. How `key_id` is derived for a non-Ed25519 key (it should
bind the algorithm so two key types cannot share an id) is deferred with the key file form (Decision 5).

---

## 2. What the new field does to the hash and the signature

- **`hash`** is `SHA-256(prev_hash || canonical(record without "hash" and "sig"))` (spec 3.1). `sig_alg`, like
  `key_id`, is neither of those two, so **when present it is inside the hashed body**. Consequences:
  - an Ed25519 record has no `sig_alg`, so its canonical bytes, its `hash`, its `sig` and the chain are
    **identical to today**. The 15 vectors and any existing v2 ledger do not change; `generate.py` followed by
    `git diff --exit-code docs/spec/vectors` (the CI step) stays empty;
  - the algorithm is committed to by the hash and therefore by the signature: it cannot be swapped on a signed
    record without breaking `hash`, which is `TAMPERED_LEDGER` before any signature is looked at.
- **Domain tag**: `"auditrail/record/v2\n"` (and `…/anchor/v2\n`) are **unchanged for every algorithm**. They
  separate *purposes*; algorithm separation already comes from `sig_alg` being inside what `hash` commits to, and
  from the verifier selecting the algorithm from the trusted key, not from attacker-controlled input alone. Putting
  the algorithm into the tag would also change the signed bytes for the default case unless special-cased.
- **Anchors**: `sig_alg` (version 3) is inside the hashed `body`, so `anchor_hash` and the signature cover it.
  `sink_ref` stays outside, as today.
- **A2A envelopes and receipts**: untouched (they have their own `v` and tags). Whether they should carry an
  algorithm is a separate decision (Decision 7).

---

## 3. What readers do

*D-14 (after the second review, T-030): a record or anchor that claims an algorithm other than its trusted key's
is `BAD_SIGNATURE` ("algorithm mismatch") **before** the implemented-or-not check, so `UNSUPPORTED_ALGORITHM` is
reached only for a key explicitly registered as a type the verifier cannot check; for `.pub` file input it cannot
occur. This supersedes the table in 3.1 where it says an unimplemented token with keys is `UNSUPPORTED_ALGORITHM`.*

*Corrected after T-026 (the first implementation followed the order below literally and let `UNSUPPORTED_*`
return early, which let an attacker without the key turn `BAD_SIGNATURE` / `REWRITTEN` into "could not judge").
The order that is implemented and specified is in spec section 6.1: `UNSUPPORTED_*` are remembered, every other
check runs, and they are reported only when nothing definite was found.*

All checks keep the existing order: read rules → chain (`TAMPERED_LEDGER`) → signatures → field rules → anchors.
The algorithm is looked at in the signature step, *after* the hash has held, and an unsupported one defers.

### 3.1 Statuses

| situation | status | tamper evidence? |
|---|---|---|
| no `sig_alg` | as today | — |
| `sig_alg` present but not a string, empty, wrong characters or case (`"Ed25519"`, `" es256"`) | `MALFORMED_RECORD` | no (malformed) |
| `sig_alg` is `"ed25519"` (non-canonical, rule 1.2.1) | `MALFORMED_RECORD` | no |
| `sig_alg` is a well-formed token **this verifier does not implement**, and trusted keys were given | **`UNSUPPORTED_ALGORITHM`** (+`bad_seq`) | **no** — an inconclusive result |
| same, no trusted keys given | not a failure: signatures are not checked anyway; the report lists "records at seq N use signature algorithm X, which this verifier cannot check" | — |
| `sig_alg` known, but the trusted key for `key_id` is of another type | `BAD_SIGNATURE` (detail "algorithm mismatch") | **yes** (confusion/downgrade attempt) |
| `format` an integer ≠ 2 | **`UNSUPPORTED_FORMAT`** | no |
| anchor of `anchor_version` 3 read by a reader that implements it but not the algorithm | `UNSUPPORTED_ALGORITHM` | no |

### 3.2 Why the existing statuses are not enough

- `UNKNOWN_KEY` means "this `key_id` is not trusted". Here the key *is* trusted and the problem is the algorithm; the
  same word would send an operator hunting for a missing key.
- `BAD_SIGNATURE` and `TAMPERED_*` are alarms. A newer writer using a newer algorithm is not an attack; reporting it
  as tampering would teach people to ignore the alarm, and reporting it as `OK` would be fail-open.
- `LEGACY_FORMAT` is specific to v0.1 ledgers.
So the new status must be **not OK, not an alarm**, in the same family as `LEGACY_FORMAT` and `SINK_UNREACHABLE`
("could not check"). The report MUST NOT contain `OK` for a ledger in which any covered record used an algorithm the
verifier does not implement while keys were given.

The mismatch case is deliberately `BAD_SIGNATURE`: a record that names an algorithm the *trusted key* cannot
produce is a signature that cannot be genuine.

### 3.3 One reader knows an algorithm, the other does not

Each reader answers from its own registry. That is *correct*, not a disagreement: Python knows `X`, Rust does not →
Python may verify, Rust says `UNSUPPORTED_ALGORITHM`. The reader-agreement rule becomes: **for every algorithm both
claim to implement, the two must return identical statuses on identical input; for an algorithm only one implements,
the other MUST return `UNSUPPORTED_ALGORITHM` and never `OK`.** Conformance vectors record the expected status per
reader capability (a vector lists the algorithms it needs).

### 3.4 Strict reading rules and the fuzz/agreement tests

- `_strict` gains one validator for the token grammar (fullmatch, not `$`: the N-1 lesson) and `format`'s integer
  check; nothing about numbers, UTF-8, lines or depth changes.
- `tests/test_fuzz.py` field mutation: add `sig_alg` insertions (valid token, junk, wrong type, `"ed25519"`) to the
  edited-field strategy; expected statuses must still agree between Python and Rust, with the unknown-token case
  expected to be `UNSUPPORTED_ALGORITHM` in both.
- `tests/test_reader_agreement.py`: one case per row of 3.1.

---

## 4. Compatibility matrix

"Old" = the readers at `0bc245b`. "New" = readers implementing this design. "Default" = Ed25519, `sig_alg` absent.

| reader ↓ / ledger → | written by old/new writer, default | new writer, non-default algorithm | v0.1 ledger |
|---|---|---|---|
| **old reader** | as today (byte-identical) | chain verifies (unknown member is hashed). With keys: the key id is not in the trusted map → `UNKNOWN_KEY` (fail-closed, misleading wording). Without keys: `OK` with "signatures not checked", as for any ledger. Non-default **anchors** → `TAMPERED_ANCHOR` ("unsupported anchor_version"): fail-closed, misleading. | `LEGACY_FORMAT` |
| **new reader** | identical result, identical bytes | algorithm known → verified; unknown → `UNSUPPORTED_ALGORITHM` (3.1) | `LEGACY_FORMAT` (the substring test runs first and is unchanged) |

Points to note:

- **No default-case ledger changes meaning for anyone.** That is the property the design is built around.
- An old reader never reports `OK` *for a signature it checked wrongly*: it checks none of the non-default ones. The
  only degradation is wording (`UNKNOWN_KEY` / `TAMPERED_ANCHOR` for "cannot read"). The new statuses fix the wording
  going forward; old readers cannot be patched retroactively.
- `LEGACY_FORMAT` is detected before anything else (substring `"format":` absent). A record with `sig_alg` but no
  `format` is therefore `LEGACY_FORMAT` and never reaches the algorithm logic.

---

## 5. Scope, files and risk

### 5.1 Files that would change

| area | files | change |
|---|---|---|
| Python core | `src/auditrail/keys.py` | an algorithm registry (one entry); `Signer` knows its `alg`; `verify_sig` dispatches on algorithm; `.pub` parser stays Ed25519-only |
| | `src/auditrail/ledger.py` | writes `sig_alg` only for a non-default signer (never for Ed25519); adds `sig_alg` to the reserved field names in `record_event` (today a caller could pass it as an ordinary event field and forge the member) |
| | `src/auditrail/verifier.py` | resolve algorithm per record; new statuses; `format` check; notes when unchecked |
| | `src/auditrail/anchor.py` | `anchor_version` 3, `BODY_KEYS_BY_VERSION`, line allow-list, build/verify |
| | `src/auditrail/_strict.py` | token and `format` validators |
| | `src/auditrail/cli.py`, `recorder.py` | status names in output/exit codes; `Signer` type; no new flags needed now |
| Rust | `verifier/src/lib.rs`, `main.rs` | same logic and statuses; no new crates while only Ed25519 exists |
| Spec | `docs/spec/evidence-format-v2.md` | sections 2, 3, 5, 6 (statuses table), registry of one algorithm |
| Vectors | `docs/spec/vectors/generate.py` + **new** case directories | **add**, never modify (below) |
| Tests | `tests/test_vectors.py` (parametrised, picks them up), `test_reader_agreement.py`, `test_fuzz.py`, new `test_algorithm_identifier.py` | |
| Docs | `SECURITY.md`, `README.md`, `docs/STATUS.md` | new statuses; "what this does not do" |

Not touched: `agent_bridge.py` (A2A), `policy.py`, the chain/canonicalisation, the domain tags.

### 5.2 Vectors

The existing 15 directories are untouched and must still regenerate byte-identically. New cases (numbering
continues, 16–):

| new vector | expected |
|---|---|
| a signed record carrying an unknown but well-formed `sig_alg` (re-hashed and "signed" so the chain is intact) | `UNSUPPORTED_ALGORITHM` with keys; `OK`+note without |
| same record, `sig_alg` of the wrong case/characters | `MALFORMED_RECORD` |
| explicit `"sig_alg":"ed25519"` | `MALFORMED_RECORD` |
| `format: 3` | `UNSUPPORTED_FORMAT` |
| an anchor line with `anchor_version` 3 and an unknown algorithm | `UNSUPPORTED_ALGORITHM` |
| an anchor with `sig_alg` but `anchor_version` 2 | `TAMPERED_ANCHOR` |

The *mismatch* status (`BAD_SIGNATURE`, "algorithm mismatch") needs a second implemented algorithm to be reachable.
With only Ed25519 it cannot be produced by a real key, so it is covered by a Python unit test with an injected
test-only algorithm entry, and gets a vector only when a second algorithm exists.

### 5.3 Size and risk

- Estimated test increment: **~35–45** (6–8 vector cases picked up by the parametrised vector tests in both
  languages, ~10 reader-agreement, ~12 unit, 3–4 fuzz strategy additions, anchor v3 cases).
- Estimated code: a few hundred lines across both languages; the Rust half is the larger risk because the reader-
  agreement and fuzz suites must keep passing byte-for-byte.
- **Breaking changes**: none for any ledger produced today. Behaviour changes: (a) new status strings that
  downstream code switching on `status` will see only for new inputs; (b) `format` ≠ 2 and explicit
  `"sig_alg":"ed25519"` become errors (neither occurs in any ledger written by this project); (c) if the trusted-key
  mapping type is widened to carry an algorithm, `load_public_keys`'s return shape changes for API users (avoidable
  by adding a parallel function).
- Biggest risk: **an unimplemented-algorithm path that quietly returns OK.** Mitigation is the explicit rule in 3.2
  and a vector for it in each language.

---

## 6. Decisions (D-12: all taken as recommended)

| # | question | decision |
|---|---|---|
| 1 | Accept or reject an explicit `"sig_alg":"ed25519"`? | **Reject** (`MALFORMED_RECORD`): one encoding per meaning keeps both readers and the fuzzers simple. |
| 2 | Is `UNSUPPORTED_ALGORITHM` a failure (non-zero exit) or an `OK` with a warning? | **Failure**, exit code 1, but documented as *inconclusive, not tampering*. A green result for something unchecked is the thing this project exists to avoid. |
| 3 | Add `UNSUPPORTED_FORMAT` for `format` ≠ 2 in the same change? | **Yes.** It is the cheap half of "format identification" and closes a silent-misread gap that exists today. |
| 4 | Anchors: new `anchor_version` 3, or an optional member inside version 2? | **Version 3**, only for non-default algorithms; the version number is the signal old readers already understand ("unsupported"). |
| 5 | Key file form and `key_id` derivation for non-Ed25519 keys | **Defer** to the change that adds the second algorithm; do not guess now. Keep the `.pub` parser Ed25519-only. |
| 6 | Reserve names (`es256`, `ml-dsa-65`) in the spec? | **No.** Reserve the *grammar* and the single value only; naming algorithms invites the impression of support. |
| 7 | Should A2A envelopes/receipts carry an algorithm too? | **Not in this change.** They have their own `v`; decide when a second algorithm is actually going to be used there. |
| 8 | Hash agility, ever? | **No**; a new hash is a new major `format`. |

---

## 7. What this design does **not** do

- It does **not** make auditrail interoperable with, or mutually verifiable against, the IETF agent-audit-trail
  (AAT) draft. Canonicalisation (JCS vs this project's form), the chain formula, the signed bytes, the key
  identifier, and the required record fields all differ; an algorithm field changes none of them. See
  `agent-team/inbox/2026-10-14-AAT草案與auditrail格式逐欄比對.md`.
- It does **not** implement ES256, ML-DSA, or any algorithm other than Ed25519, and it does not choose, name or
  reserve a second one.
- It does **not** change SHA-256, the canonical JSON form, the chain, the domain tags, timestamps, or any rule in
  section 2 of the spec.
- It does **not** add multiple or hybrid signatures, cross-signing, or key-rotation machinery beyond what exists.
- It does **not** change A2A envelopes or receipts.
- It does **not** promise interoperability beyond algorithm agility: a ledger written with a future algorithm is
  verifiable only by a verifier that implements it, and the old verifiers will say "cannot read" in the words of
  section 4, not "OK".
- It does **not** make the unwrapped-tools, key-custody, witness or tail limitations in `SECURITY.md` any smaller.
