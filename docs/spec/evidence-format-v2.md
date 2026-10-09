# auditrail evidence format v2

Status: draft, implemented by `auditrail` (Python) and `verifier/` (Rust). The two
implementations are independent and must agree on every case in
[`vectors/`](vectors/). If you write a third, run it against those vectors.

The words MUST and MUST NOT are used in the RFC 2119 sense.

## 1. Goal and non-goals

A third party who does not trust the operator of an AI agent should be able to
check, offline and with a single small program, that a record of what the agent
did **was not rewritten after the fact**, and to see exactly which things the
check did *not* cover.

Non-goals: judging whether a recorded action was safe, detecting malicious
content, or proving that nothing happened outside the recorded tool set.
Section 8 lists what verification can and cannot prove.

## 2. Conventions

- **Canonical JSON** (used wherever bytes are hashed or signed): UTF-8; object
  keys sorted by Unicode code point; separators `,` and `:` with no whitespace;
  strings escaped only where JSON requires it (`"`, `\`, and U+0000-U+001F, using
  `\b \f \n \r \t` where they exist and `\u00xx` in lowercase hex otherwise);
  non-ASCII characters are written as themselves, not as `\u` escapes.
  Records MUST NOT contain floating-point numbers; durations are integer
  microseconds, and any other fractional value is a string.
- **Hash**: SHA-256, written as 64 lowercase hex characters.
- **Signature**: Ed25519 (RFC 8032), written as 128 lowercase hex characters.
  Keys are 32 bytes, written as 64 hex characters.
- **key_id**: the first 16 hex characters of `SHA-256(raw 32-byte public key)`.
- **Timestamps**: UTC, `YYYY-MM-DDTHH:MM:SSZ`.
- A ledger is a UTF-8 text file, one canonical JSON object per line, `\n` line endings.

### Reading files (what a verifier MUST accept and reject)

Two verifiers that disagree about an odd input give an attacker the input the weaker
one accepts, so reading is specified exactly. A verifier MUST:

- reject a file that is not valid UTF-8 (`TAMPERED_LEDGER`, no `bad_seq`);
- split lines on `\n` only, ignore one trailing `\r` per line, and skip a line made only
  of spaces, tabs and `\r`. Any other character (U+2028, U+0085, form feed, ...) is
  content, not a line break or blank;
- parse each remaining line as one JSON object (RFC 8259), a later duplicate key
  replacing an earlier one, and reject: `NaN`/`Infinity`, any number with a fraction or
  exponent, `-0`, any integer outside -2^63..2^63-1, a lone surrogate (in a string or a
  key), a byte-order mark, and nesting deeper than 64 levels (the record object is level 1).
  A rejected line is `TAMPERED_LEDGER` with `bad_seq` = the number of records read before it;
- treat hex fields (`hash`, `sig`, ...) as lowercase ASCII only: a signature with a space,
  a capital letter, a prefix, or the wrong length is invalid, never "close enough";
- treat `true`/`false` as not integers (Python's `True == 1` must not leak into a comparison).

A timestamp is valid only as `YYYY-MM-DDTHH:MM:SSZ` with ASCII digits, a real calendar date
(leap years included), hour <= 23, minute and second <= 59, and year 1970-9999.

## 3. Records

Every record has:

| field | type | meaning |
|---|---|---|
| `format` | int | `2` (absent in v0.1 records, which verify the same way) |
| `seq` | int | 0 for the first record, then +1 each; no gaps |
| `ts` | string | when the recorder wrote it |
| `kind` | string | `call`, `heartbeat`, `a2a_send`, `a2a_recv`, `a2a_ack`. Absent in v0.1 records, meaning `call` |
| `prev_hash` | string | `hash` of the previous record; 64 zeros for `seq` 0 |
| `hash` | string | see 3.1 |
| `key_id`, `sig` | string | present when the recorder signs (see 3.2) |

Further fields depend on `kind`.

**`call`**: `agent_id`, `session_id`, `trace_id`, `policy_version`, `tool`,
`categories` (sorted list), `args_digest`, `decision` (`allow`, `deny`,
`sandboxed`, `error`), `reason` (string or null), `result_digest` (string or
null), `duration_us` (int or null). Arguments and results are never stored,
only `SHA-256` of their canonical JSON. For `error`, `reason` is the exception
type plus a digest of its message unless the operator opted into storing the text.

**`heartbeat`**: `recorder_id`, `tools` (sorted list of wrapped tool names),
`policy_version`, `policy_hash`, `calls_attempted`, `calls_recorded` (counts since
this writer's previous heartbeat), `interval_s`.

**`a2a_send` / `a2a_recv` / `a2a_ack`**: `agent_id`, `peer`, `msg_id`,
`msg_digest` (SHA-256 of the canonical signed envelope), and for `a2a_recv` a
`status` of `accepted` or `rejected`. See section 9.

### 3.1 Hash

```
hash = SHA-256( prev_hash || canonical(record without "hash" and "sig") )
```

`||` is concatenation of the 64-character `prev_hash` string and the canonical
JSON text, both as UTF-8. `key_id`, when present, is part of the hashed body.

### 3.2 Signature

```
sig = Ed25519( "auditrail/record/v2\n" || hash )
```

where `hash` is the 64-character hex string as ASCII bytes. The domain tag
prevents a signature made for one purpose from being replayed for another.
`sig` is outside the hashed body.

## 4. Why signatures, and what they need

A hash chain alone proves only internal consistency: anyone who can write the
file can edit a record and recompute every later hash. Signing makes a rewrite
require the recorder's private key. This holds only if the agent, and anyone
who might want to rewrite history, cannot read that key (section 7).

## 5. Anchors and witnesses

An **anchor** pins the ledger head at a moment:

```
body   = { anchor_version, seq, head_hash, prev_anchor, created_at [, key_id] }
anchor_hash = SHA-256( canonical(body) )
line   = body + { anchor_hash [, sig] [, sink_ref] }
sig    = Ed25519( "auditrail/anchor/v2\n" || anchor_hash )          (version 2 only)
```

- `anchor_version` 1 is unsigned; 2 carries `key_id` (inside `body`) and `sig`.
- `prev_anchor` is the previous anchor's `anchor_hash` (64 zeros for the first),
  so the anchors file is itself a chain.
- `sink_ref` says where a copy was published; it is not hashed.
- An anchor line MUST NOT contain any other field.

A **witness** is a place the ledger owner cannot rewrite alone (a public git
repository, a timestamping service, a customer's storage). The owner publishes
each anchor line there. A verifier holding a copy from the witness does not
need the owner's `anchors.jsonl` at all. Anchors contain only hashes and times.

## 6. Verification

Run these checks in order and stop at the first failure. Each failure has a
status; the optional inputs decide which checks run.

| # | check | failure status |
|---|---|---|
| 1 | the file reads under the rules in section 2; `seq` is the integer 0,1,2,...; `prev_hash` links; `hash` recomputes | `TAMPERED_LEDGER` (+`bad_seq`) |
| 2 | **if trusted public keys were given:** every record has a non-empty string `key_id` and `sig`; the key is trusted; the signature verifies | `UNSIGNED_RECORD`, `UNKNOWN_KEY`, `BAD_SIGNATURE` (+`bad_seq`) |
| 2b | after a record's hash (and signature, if keys were given) hold: `ts` is a valid timestamp; `kind`, if present, is a string; a `heartbeat` has `tools` (list of strings) and integer `calls_attempted` / `calls_recorded` | `MALFORMED_RECORD` (+`bad_seq`) |
| 3 | **if an anchors file was given:** each line is well formed and its `anchor_hash` recomputes; `prev_anchor` links; with keys given, version-2 lines are signed by a trusted key and version-1 lines are refused; the ledger has a record at each anchored `seq` whose `hash` equals `head_hash` | `TAMPERED_ANCHOR`, `UNSIGNED_ANCHOR`, `UNKNOWN_KEY`, `BAD_SIGNATURE`, `TRUNCATED`, `REWRITTEN` |
| 4 | **if a witness copy was given:** the same per-line and ledger checks as 3 (without `prev_anchor` linking) | same |
| 5 | **if a maximum gap was given:** the ledger has at least one heartbeat (`NO_HEARTBEAT`); no heartbeat reports `calls_attempted != calls_recorded` (`UNRECORDED_CALLS`); no interval between the first record, each heartbeat, and the last record exceeds the gap (`HEARTBEAT_GAP`) | as named |

On success the verifier MUST report `OK` together with `anchored_upto` (highest
anchored `seq`, or null) and `unanchored_tail` (records after it), and MUST list
every check it was not asked to run. A verifier that prints a bare "OK" is not conformant.

`SINK_UNREACHABLE` (a configured witness could not be read) is not tampering
evidence, but the verifier MUST NOT claim the anchor was checked.

## 7. Key custody (what makes the signatures mean something)

- The recorder's private key MUST be unreadable by the agent: a separate OS user,
  a separate host, or a KMS/TPM that signs on request. `auditrail recorder`
  provides the separate process; the operating-system separation is yours to arrange.
- Publish the public key with the first anchor, somewhere the operator cannot
  quietly change. Rotation: start a new key, anchor with both for an overlap,
  retire the old one; verifiers pass both public keys.
- Anchors only help if the witness copy exists. An anchor nobody else holds is
  just another line the operator can delete.

## 8. What verification proves and does not

Proves, for records up to the last witnessed anchor and given the trusted keys:
they were not edited, reordered, inserted, or removed; they were written by the
holder of the recorder key; and the recorder's own count of calls it saw matches
what it wrote.

Does **not** prove:

- anything about records after the last anchor (the tail);
- that every action went through the recorder. Tools that were not wrapped leave
  no trace, and heartbeats list only what was wrapped. Closing this needs an
  architecture in which the agent holds no credentials except through the guard,
  and cross-checking against the called system's own logs;
- anything if the recorder host, or the recorder key, is compromised;
- anything if the witness colludes with the operator;
- that a recorded action was safe, or that a message's content was benign.

## 9. Agent-to-agent messages

Each agent has its own Ed25519 key; a registry maps agent ids to public keys.

```
envelope body = { v:2, msg_id, sender, recipient, ts_ms, trace_id, categories, payload, key_id }
sig           = Ed25519( "auditrail/a2a/v2\n" || canonical(body) )
msg_digest    = SHA-256( canonical(body + {sig}) )
receipt body  = { v:2, msg_digest, recipient, received_ms, key_id }
receipt sig   = Ed25519( "auditrail/receipt/v2\n" || canonical(receipt body) )
```

The sender writes `a2a_send` with `msg_digest`; the receiver verifies, writes
`a2a_recv` (keeping the sender's signature), and returns the receipt; the
sender verifies it and writes `a2a_ack`. Cross-checking two ledgers
(`auditrail reconcile`) then reports `RECV_WITHOUT_SEND`, `SEND_WITHOUT_RECV`
and `ACK_WITHOUT_RECV`. `categories` carries the sender workflow's trifecta
categories so the receiver's policy inherits them.

A signed message proves who sent it. It does not make its content safe.

## 10. Conformance

[`vectors/`](vectors/) holds thirteen cases (ledgers, keys, witness copies,
`expected.json`) covering a valid ledger, edits with and without recomputed
hashes, truncation, a rebuilt ledger under another key, a heartbeat gap, unrecorded
calls, a nonsense timestamp, a float, and a non-UTF-8 file. `vectors/generate.py`
regenerates them byte-for-byte.

Vectors prove the common cases. For the rest, the reference implementations are also
held to each other by property-based tests: random ledgers must verify in both; any
field edit or raw byte corruption must be rejected, and with the same status, by both;
re-hashing after an edit must still fail the signature check; and garbage input must
produce a status, never a crash (`tests/test_fuzz.py`, `tests/test_reader_agreement.py`,
`verifier/tests/robust.rs`). A third implementation should be run against the same suites.
