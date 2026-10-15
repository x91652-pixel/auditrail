"""`auditrail report`: a human-readable account of what a verification found and what it did not examine.

A report is a *rendering* of the verifier's results, not new evidence and not a verdict:

* it is a pure function of its input files, the auditrail version and the options (no clock, no network, no
  LLM); the same inputs give byte-identical output, and the only line that can differ is an optional,
  explicitly requested timestamp, which is outside the fingerprint;
* the overall status is the verifier's own (`verify_all`, spec section 6.1); the per-section detail is
  collected so that a later finding is still shown after an earlier failure, but nothing computed from records
  that failed the chain or signature checks is presented as fact;
* every status string the verifiers can emit has an entry in STATUS_TABLE, and an unknown status is shown as
  inconclusive, never as consistent;
* the section "What this report does not prove" is fixed and cannot be switched off.

All user-facing words live in the tables at the top of this module.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Optional

from . import __version__, _strict
from .anchor import _anchor_lines, verify_anchors, verify_witness_file
from .keys import key_algorithm, key_id_for, load_public_keys
from .reconcile import reconcile
from .verifier import INCONCLUSIVE, _read_records, check_chain, check_heartbeats, verify_all

REPORT_VERSION = 1
DEFAULT_MAX_ROWS = 50

# --------------------------------------------------------------------------------------------- wording
# class: consistent | definite | malformed | inconclusive | completeness
STATUS_TABLE: dict[str, dict[str, str]] = {
    "OK": dict(
        cls="consistent", label="No inconsistency found",
        means="The checks that were run found no inconsistency in the evidence they covered.",
        not_means="It does not mean the recorded actions were appropriate, that nothing happened outside the "
                  "wrapped tools, or that anything not listed under 'Checks that ran' was examined."),
    "TAMPERED_LEDGER": dict(
        cls="definite", label="Records do not match their own hashes or links",
        means="From the reported seq onward the records do not match the hash chain, or the file could not be "
              "read under the format's rules. Records before that point are consistent with each other.",
        not_means="It does not say who changed the file or why."),
    "UNSIGNED_RECORD": dict(
        cls="definite", label="A record carries no signature",
        means="Signatures were required and a record has none.",
        not_means="It does not say the record's content is wrong, only that nothing vouches for it."),
    "UNKNOWN_KEY": dict(
        cls="definite", label="A record names a key that was not given",
        means="A record names a key id that is not among the trusted keys supplied.",
        not_means="It may simply be the wrong key file; it does not by itself show an alteration."),
    "BAD_SIGNATURE": dict(
        cls="definite", label="A signature does not verify or names the wrong algorithm",
        means="A record or anchor has a signature that does not verify under the trusted key, or it claims a "
              "signature algorithm other than its trusted key's (\"algorithm mismatch\").",
        not_means="It does not say who made the change."),
    "MALFORMED_RECORD": dict(
        cls="malformed", label="A record breaks the format's field rules",
        means="The record is internally consistent but a field the format constrains is not valid.",
        not_means="It is not a hash or signature failure, and it does not say the record was altered."),
    "TAMPERED_ANCHOR": dict(
        cls="definite", label="The anchors file or witness copy was altered",
        means="An anchor line is malformed, does not match its own hash, or does not chain to the previous one.",
        not_means="It does not say the ledger itself was altered."),
    "UNSIGNED_ANCHOR": dict(
        cls="definite", label="An anchor lacks the required signature",
        means="Signatures were required and an anchor line is unsigned.",
        not_means="It does not say the ledger was altered."),
    "TRUNCATED": dict(
        cls="definite", label="Records the witness vouches for are missing",
        means="The witness copy holds an anchor for a record the ledger no longer has.",
        not_means="It does not say how or by whom the records were removed."),
    "REWRITTEN": dict(
        cls="definite", label="A witnessed record was changed",
        means="A record that the witness copy vouches for no longer matches what was published.",
        not_means="It does not say what the original content was."),
    "SINK_MISMATCH": dict(
        cls="definite", label="The witness does not hold a claimed anchor",
        means="An anchor the owner's file says was published is not in the witness.",
        not_means="It does not say the ledger was altered."),
    "SINK_UNREACHABLE": dict(
        cls="inconclusive", label="A witness could not be read",
        means="A configured witness could not be read, so those anchors were not checked.",
        not_means="It is not evidence of an alteration, and it does not mean the anchors were checked."),
    "NO_HEARTBEAT": dict(
        cls="completeness", label="No heartbeat was recorded",
        means="A heartbeat limit was given and the ledger holds no heartbeat record at all.",
        not_means="It does not show what, if anything, ran without being recorded."),
    "UNRECORDED_CALLS": dict(
        cls="completeness", label="The recorder counted calls it did not record",
        means="A heartbeat reports more calls intercepted than recorded.",
        not_means="It does not say what those calls were."),
    "HEARTBEAT_GAP": dict(
        cls="completeness", label="A silent period exceeds the limit",
        means="There is a period longer than the given limit with no heartbeat.",
        not_means="It does not show what happened during the period."),
    "LEGACY_FORMAT": dict(
        cls="inconclusive", label="An old (v0.1) ledger",
        means="The ledger predates signed evidence and is not examined by these checks.",
        not_means="It is not a finding about the ledger's content; `verify --legacy-v01` gives only a "
                  "hash-chain check."),
    "UNSUPPORTED_ALGORITHM": dict(
        cls="inconclusive", label="A signature algorithm this verifier cannot check",
        means="The trusted key is registered as an algorithm this verifier does not implement, so signatures "
              "made with it could not be checked. For a key read from a file this status cannot occur: such a "
              "key is Ed25519, and a record claiming another algorithm is reported as BAD_SIGNATURE "
              "(\"algorithm mismatch\").",
        not_means="It can be provoked by someone who does not hold the key, so it never means the records "
                  "were left unchanged; a definite finding always outranks it."),
    "UNSUPPORTED_FORMAT": dict(
        cls="inconclusive", label="A record format this verifier does not read",
        means="A record declares a format other than the one this verifier reads, although its hash holds.",
        not_means="It can be provoked by someone who does not hold the key, so it never means the records "
                  "were left unchanged; a definite finding always outranks it."),
}
FINDING_TABLE: dict[str, dict[str, str]] = {
    "MISMATCH": dict(label="Messages recorded by one side only",
                     means="At least one agent-to-agent message appears in only one of the supplied ledgers."),
    "RECV_WITHOUT_SEND": dict(label="Received, never recorded as sent",
                              means="A receiver recorded a message that the sender's ledger does not contain."),
    "SEND_WITHOUT_RECV": dict(label="Sent, never recorded as received",
                              means="A sender recorded a message that the receiver's ledger does not contain."),
    "ACK_WITHOUT_RECV": dict(label="Receipt without a recorded receive",
                             means="A receipt was recorded for a message the receiver's ledger does not hold."),
}
UNKNOWN_STATUS = dict(
    cls="inconclusive", label="A status this report version cannot explain",
    means="The verifier returned a status that this report has no wording for.",
    not_means="It is shown as inconclusive and is never treated as a consistent result.")

# Statements that are always printed, whatever SECURITY.md generated (a floor, not a replacement).
LIMITS_FLOOR = (
    "Only tool calls that went through the recorder's wrapped tools are seen here; an action by an unwrapped "
    "tool leaves no record.",
    "Records after the last anchor held by a witness are not covered by it.",
    "Nothing is established if the recorder's host or signing key was compromised.",
    "A witness that colludes with the operator defeats the anchors.",
    "This report examines evidence; it does not judge whether the recorded actions were appropriate.",
)

NOT_VOCAB = re.compile(
    r"\b(safe|safely|safety|secure|securely|security|compliant|compliance|certified|certify|certification|"
    r"approved|approve|approval|passed|guarantee|guaranteed|guarantees|audited)\b", re.I)

REASON_CLASSES = (
    ("lethal_trifecta", "lethal_trifecta"),
    ("unclassified_tool", "unclassified_tool"),
    ("state_change_after_untrusted", "state_change_after_untrusted"),
    ("label_conflict", "label_conflict"),
)


def explain(status: str) -> dict[str, str]:
    return STATUS_TABLE.get(status) or UNKNOWN_STATUS


def _is_definite(status: str) -> bool:
    return explain(status)["cls"] in ("definite", "malformed", "completeness")


# --------------------------------------------------------------------------------------------- limits
def _limits() -> tuple[str, tuple]:
    from . import _limits as gen

    return gen.SOURCE_SHA256, gen.ITEMS


# --------------------------------------------------------------------------------------------- collection
def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_class(reason: Optional[str]) -> str:
    r = reason or ""
    for prefix, name in REASON_CLASSES:
        if r.startswith(prefix):
            return name
    if "is not allow-listed" in r:
        return "not_allow_listed"
    return "other"


def _tool_changes(beats: list[dict]) -> list[dict]:
    out, prev = [], None
    for b in beats:
        if prev is not None:
            added = sorted(set(b.get("tools", [])) - set(prev.get("tools", [])))
            removed = sorted(set(prev.get("tools", [])) - set(b.get("tools", [])))
            if added or removed:
                out.append({"seq": b["seq"], "ts": b["ts"], "added": added, "removed": removed})
        prev = b
    return out


def _policy_timeline(records: list[dict]) -> list[dict]:
    runs: list[dict] = []
    for r in records:
        h = r.get("policy_hash")
        if r.get("kind", "call") != "call" or h is None:
            continue
        if runs and runs[-1]["policy_hash"] == h:
            runs[-1]["last_seq"], runs[-1]["last_ts"] = r["seq"], r["ts"]
        else:
            runs.append({"policy_hash": h, "policy_version": r.get("policy_version"), "first_seq": r["seq"],
                         "first_ts": r["ts"], "last_seq": r["seq"], "last_ts": r["ts"]})
    return runs


def build_report(
    ledger_path,
    *,
    public_key_paths=(),
    anchors_path=None,
    witness_path=None,
    git_repo=None,
    max_gap_s: Optional[int] = None,
    peer_ledgers=(),
    agents=(),
    title: Optional[str] = None,
    note: Optional[str] = None,
    redact: bool = False,
    redact_salt: Optional[str] = None,
    generated_at: Optional[str] = None,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> dict:
    """Collect everything a report states, as plain data. Raises FileNotFoundError/ValueError on unusable input."""
    ledger = Path(ledger_path)
    raw = ledger.read_bytes()  # FileNotFoundError: no report is produced for evidence that cannot be read
    keys = load_public_keys([Path(p) for p in public_key_paths]) if public_key_paths else None  # ValueError
    sinks = {}
    if git_repo:
        from .anchor import GitSink

        sinks["git"] = GitSink(git_repo)

    inputs = [{"role": "ledger", "name": ledger.name, "sha256": _sha(raw), "bytes": len(raw)}]
    for role, p in [("public key", p) for p in public_key_paths] + [("anchors", anchors_path), ("witness copy", witness_path)] \
            + [("peer ledger", p) for p in peer_ledgers]:
        if p:
            b = Path(p).read_bytes()
            inputs.append({"role": role, "name": Path(p).name, "sha256": _sha(b), "bytes": len(b)})

    overall = verify_all(ledger, public_keys=keys, anchors_path=anchors_path, sinks=sinks or None,
                         witness_path=witness_path, max_gap_s=max_gap_s)
    records, read_problem = _read_records(ledger)
    chain_problem = None if read_problem else check_chain(ledger, public_keys=keys, records=records)
    if read_problem is not None:
        chain_state = "unreadable" if read_problem["status"] != "LEGACY_FORMAT" else "legacy"
    elif chain_problem is None:
        chain_state = "consistent"
    elif chain_problem["status"] in INCONCLUSIVE:
        chain_state = "inconclusive"
    else:
        chain_state = "failed"
    evaluable = chain_state in ("consistent", "inconclusive")

    data: dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "auditrail_version": __version__,
        "title": title,
        "note": note,
        "redacted": redact,
        "max_rows": max_rows,
        "inputs": inputs,
        "overall": {"status": overall["status"], "detail": overall.get("detail", ""),
                    "bad_seq": overall.get("bad_seq"), "anchored_upto": overall.get("anchored_upto"),
                    "unanchored_tail": overall.get("unanchored_tail")},
        "chain": {"state": chain_state,
                  "status": (read_problem or chain_problem or {}).get("status", "OK"),
                  "detail": (read_problem or chain_problem or {}).get("detail", ""),
                  "bad_seq": (read_problem or chain_problem or {}).get("bad_seq")},
        "signatures_required": keys is not None,
        "unchecked_algorithms": overall.get("unchecked_algorithms", []),
    }

    # --- scope
    if evaluable and records:
        kinds: dict[str, int] = {}
        for r in records:
            kinds[r.get("kind", "call")] = kinds.get(r.get("kind", "call"), 0) + 1
        data["scope"] = {"records": len(records), "first_seq": records[0]["seq"], "last_seq": records[-1]["seq"],
                         "first_ts": records[0].get("ts"), "last_ts": records[-1].get("ts"), "kinds": kinds}
    elif evaluable:
        data["scope"] = {"records": 0, "kinds": {}}
    else:
        data["scope"] = None
        prefix = chain_problem.get("bad_seq") if chain_problem else None
        data["verified_prefix"] = prefix if isinstance(prefix, int) else None

    # --- keys
    key_rows = []
    for kid, pub in sorted((keys or {}).items()):
        key_rows.append({"key_id": kid, "fingerprint_sha256": hashlib.sha256(bytes.fromhex(pub)).hexdigest(),
                         "algorithm": key_algorithm(keys, kid)})
    data["keys"] = key_rows
    if evaluable:
        data["record_key_ids"] = sorted({r["key_id"] for r in records if isinstance(r.get("key_id"), str)})
        data["record_algorithms"] = sorted({r.get("sig_alg", "ed25519") for r in records if "sig" in r})

    # --- anchors and witness
    def anchor_section(path, runner):
        if path is None:
            return {"given": False}
        lines, _ = _anchor_lines(Path(path))
        rows = [{"seq": a.get("seq"), "created_at": a.get("created_at"), "key_id": a.get("key_id"),
                 "version": a.get("anchor_version"), "sig_alg": a.get("sig_alg", "ed25519" if "sig" in a else None),
                 "sink_ref": a.get("sink_ref")} for _, a in lines if isinstance(a, dict)]
        if not evaluable:
            return {"given": True, "evaluated": False, "lines": len(rows), "rows": []}
        res = runner()
        return {"given": True, "evaluated": True, "status": res["status"], "detail": res.get("detail", ""),
                "anchored_upto": res.get("anchored_upto"), "unanchored_tail": res.get("unanchored_tail"),
                "lines": len(rows), "rows": rows[:max_rows], "rows_hidden": max(0, len(rows) - max_rows)}

    data["anchors"] = anchor_section(
        anchors_path, lambda: verify_anchors(ledger, anchors_path, sinks=sinks or None, public_keys=keys,
                                             records=records))
    data["witness"] = anchor_section(
        witness_path, lambda: verify_witness_file(records, witness_path, public_keys=keys))
    covered = [s.get("anchored_upto") for s in (data["anchors"], data["witness"])
               if s.get("evaluated") and s.get("anchored_upto") is not None]
    if evaluable:
        upto = max(covered) if covered else None
        total = len(records)
        data["coverage"] = {"anchored_upto": upto,
                            "unanchored_tail": (total - (upto + 1)) if upto is not None else total,
                            "tail_first_seq": (upto + 1) if upto is not None else (records[0]["seq"] if records else None),
                            "tail_last_seq": records[-1]["seq"] if records else None}
    else:
        data["coverage"] = None

    # --- heartbeats
    beats = [r for r in records if r.get("kind") == "heartbeat"] if evaluable else []
    hb: dict[str, Any] = {"evaluated": evaluable, "max_gap_s": max_gap_s, "count": len(beats)}
    if evaluable:
        hb["recorders"] = sorted({str(b.get("recorder_id")) for b in beats})
        hb["tool_lists"] = sorted({t for b in beats for t in b.get("tools", [])})
        hb["calls_attempted"] = sum(b.get("calls_attempted", 0) for b in beats if isinstance(b.get("calls_attempted"), int))
        hb["calls_recorded"] = sum(b.get("calls_recorded", 0) for b in beats if isinstance(b.get("calls_recorded"), int))
        hb["tool_changes"] = _tool_changes(beats)
        if max_gap_s is not None:
            problem, _changes = check_heartbeats(records, max_gap_s)
            hb["status"] = problem["status"] if problem else "OK"
            hb["detail"] = problem["detail"] if problem else "no period longer than the limit without a heartbeat"
            hb["gaps"] = (problem or {}).get("gaps", [])
        else:
            hb["status"] = None
    data["heartbeats"] = hb

    # --- policy timeline
    data["policy"] = {"evaluated": evaluable, "runs": _policy_timeline(records) if evaluable else []}

    # --- refusals
    ref: dict[str, Any] = {"evaluated": evaluable}
    if evaluable:
        decisions: dict[str, int] = {}
        by_class: dict[str, int] = {}
        by_tool: dict[str, int] = {}
        by_agent: dict[str, int] = {}
        for r in records:
            if r.get("kind", "call") != "call":
                continue
            d = r.get("decision", "?")
            decisions[d] = decisions.get(d, 0) + 1
            if d in ("deny", "error"):
                c = _reason_class(r.get("reason")) if d == "deny" else "error"
                by_class[c] = by_class.get(c, 0) + 1
                by_tool[str(r.get("tool"))] = by_tool.get(str(r.get("tool")), 0) + 1
                by_agent[str(r.get("agent_id"))] = by_agent.get(str(r.get("agent_id")), 0) + 1
        ref.update(decisions=decisions, by_class=by_class, by_tool=by_tool, by_agent=by_agent)
    data["refusals"] = ref

    # --- agent-to-agent
    a2a: dict[str, Any] = {"given": bool(peer_ledgers)}
    if peer_ledgers:
        if evaluable:
            res = reconcile([str(ledger), *[str(p) for p in peer_ledgers]], public_keys=keys, agents=list(agents))
            own_kids = set(data.get("record_key_ids") or [])
            peers = []
            for pp in peer_ledgers:
                prs, prob = _read_records(Path(pp))
                kids = sorted({r["key_id"] for r in prs if isinstance(r.get("key_id"), str)}) if not prob else []
                peers.append({"name": Path(pp).name, "records": None if prob else len(prs), "key_ids": kids,
                              "same_content": (not prob) and prs == records,
                              "same_key": bool(own_kids & set(kids)), "signatures_checked": keys is not None})
            same = [x for x in peers if x["same_content"]]
            a2a.update(evaluated=True, status=res["status"], detail=res.get("detail", ""),
                       matched=res.get("matched"), unverifiable=res.get("unverifiable"),
                       peer_same_as_ledger=len(same), peers_given=len(peer_ledgers), peers=peers,
                       findings=res.get("findings", [])[:max_rows],
                       findings_hidden=max(0, len(res.get("findings", [])) - max_rows),
                       rejected=len(res.get("rejected", [])))
        else:
            a2a["evaluated"] = False
    else:
        a2a["a2a_records_in_this_ledger"] = {k: v for k, v in (data["scope"] or {}).get("kinds", {}).items()
                                              if k.startswith("a2a")}
    data["a2a"] = a2a

    # --- what ran and what did not, from the outcomes (not from the flags)
    n_records = len(records) if records else 0
    readable = chain_state in ("consistent", "inconclusive", "failed")
    nc = []
    ran = []
    if chain_state == "legacy":
        nc.append("The ledger was not examined (v0.1 format; see LEGACY_FORMAT).")
    elif chain_state == "unreadable":
        nc.append("The ledger could not be read, so nothing was examined (see the verifier status).")
    elif overall["status"] in ("UNSUPPORTED_ALGORITHM", "UNSUPPORTED_FORMAT"):
        nc.append("Records or anchors in a format or algorithm this verifier does not implement could not be "
                  f"checked ({overall['status']}); the result is incomplete.")
    if n_records == 0 and evaluable:
        nc.append("The ledger holds no records: nothing was examined, so no check had anything to find.")
    elif readable:
        ran.append("Hash chain and field rules over the records.")
        if keys is not None:
            ran.append("Signatures against the trusted keys given.")
    if keys is None and n_records:
        nc.append("Signatures were NOT CHECKED (no public key was given): anyone who could write the file could "
                  "have rewritten the chain consistently.")
    effective = []
    for name, sec in (("owner's anchors file", data["anchors"]), ("witness copy", data["witness"])):
        if not sec.get("given"):
            continue
        if sec.get("evaluated") is False:
            nc.append(f"The {name} was not evaluated because the records failed an earlier check.")
        elif sec.get("status") == "SINK_UNREACHABLE":
            nc.append(f"The {name} could not be read: those anchors were not checked.")
        elif sec.get("lines", 0) == 0:
            nc.append(f"The {name} that was given holds no anchors: nothing was compared against it.")
        else:
            effective.append(name)
            ran.append(f"The {name} ({sec['lines']} line(s)).")
    if not effective and n_records:
        nc.append("No anchor or witness copy was available to compare against: removal of records and whole-chain "
                  "rewrites are not detectable from this input.")
    if max_gap_s is None:
        if n_records:
            nc.append("Heartbeats were NOT CHECKED (no gap limit was given): silent periods are not detectable.")
    elif evaluable and n_records:
        ran.append(f"Heartbeats against a limit of {max_gap_s} seconds.")
    for alg in data["unchecked_algorithms"]:
        nc.append(f"Signatures made with algorithm '{alg}' were NOT CHECKED: this verifier cannot check them.")
    if a2a.get("given"):
        if not a2a.get("evaluated"):
            nc.append("The agent-to-agent messages were not evaluated because the records failed an earlier check.")
        else:
            n_find = len(a2a.get("findings", [])) + a2a.get("findings_hidden", 0)
            compared = (a2a.get("matched") or 0) + n_find
            if a2a["peer_same_as_ledger"]:
                nc.append(f"{a2a['peer_same_as_ledger']} of the {a2a['peers_given']} peer ledger(s) given has the same "
                          "content as the ledger itself: a ledger cannot be reconciled against itself, and such a "
                          "peer says nothing about the other side.")
            if a2a.get("unverifiable"):
                nc.append(f"{a2a['unverifiable']} message(s) could not be compared: the ledger of the other side "
                          "was not supplied.")
            if keys is None:
                nc.append("Peer ledger signatures were not checked (no public key was given).")
            if compared and not (a2a["peer_same_as_ledger"] == a2a["peers_given"]):
                desc = "; ".join(
                    f"{pr['records'] if pr['records'] is not None else 'unreadable'} record(s), key id(s) "
                    f"{', '.join(pr['key_ids']) or 'none'}"
                    + (", same signing key as the ledger: this does not show the other side is independent"
                       if pr["same_key"] else "") for pr in a2a["peers"])
                ran.append(f"Agent-to-agent messages: {a2a.get('matched') or 0} matched, {n_find} finding(s); "
                           f"peer ledgers: {desc}.")
            else:
                nc.append("No agent-to-agent message was compared against another party's record.")
    data["checks_ran"] = ran
    data["not_checked"] = nc

    # --- redaction: only the values of known name fields are replaced; statuses and structure keys are never touched
    data["redacted"] = redact
    data["redaction"] = {"salted": bool(redact_salt)} if redact else None
    if redact:
        status_before = data["overall"]["status"]
        data = _redact(data, records, agents, redact_salt, [ledger, *[Path(p) for p in public_key_paths],
                                                           *[Path(p) for p in (anchors_path, witness_path) if p],
                                                           *[Path(p) for p in peer_ledgers]])
        if data["overall"]["status"] != status_before:
            raise ValueError("redaction changed the verifier status; no report is produced")

    # --- fingerprint (everything above; the optional stamp is added afterwards and is not part of it)
    body = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    data["fingerprint_sha256"] = _sha(body.encode("utf-8"))
    data["generated_at"] = generated_at
    return data


REDACTION_NOT_MASKED = ("policy version strings, timestamps, counts, key ids, policy hashes, message ids, input file "
                        "SHA-256 values and sizes, and any name that does not appear in the records")


def _code(kind: str, name: str, salt: Optional[str]) -> str:
    seed = f"{kind}:{name}" if not salt else f"{salt}:salt:{kind}:{name}"
    return f"{kind}-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]


def _redact(data: dict, records: list, agents, salt: Optional[str], input_paths: list) -> dict:
    """Replace names in the fields that carry them, by whole value or whole word. Structure keys and statuses are
    left alone; --title and --note are not touched (and the report says so)."""
    names: dict[str, set] = {"agent": set(), "tool": set(), "recorder": set()}
    for r in records:
        if not isinstance(r, dict):
            continue
        for key, kind in (("agent_id", "agent"), ("peer", "agent"), ("tool", "tool"), ("recorder_id", "recorder")):
            if isinstance(r.get(key), str):
                names[kind].add(r[key])
        for t in r.get("tools", []) if isinstance(r.get("tools"), list) else []:
            if isinstance(t, str):
                names["tool"].add(t)
    names["agent"].update(a for a in agents if isinstance(a, str))
    maps = {k: {n: _code(k, n, salt) for n in v if n} for k, v in names.items()}
    flat: dict[str, str] = {}
    for k in ("recorder", "tool", "agent"):  # earlier kinds lose on a clash; agents win
        flat.update(maps[k])
    withheld = {}
    for p in input_paths:
        for t in {str(p), p.name}:
            if t:
                withheld[t] = "(name withheld)"
    word_map = {**flat, **withheld}
    for n, code in flat.items():  # the verifier embeds some names with repr(); those spellings are replaced too
        word_map.setdefault(repr(n), code)
        word_map.setdefault(repr(n)[1:-1], code)
    rx = None
    if word_map:
        alt = "|".join(re.escape(n) for n in sorted(word_map, key=len, reverse=True))
        rx = re.compile(r"(?<![A-Za-z0-9_])(?:" + alt + r")(?![A-Za-z0-9_])")

    def text(v):
        return rx.sub(lambda m: word_map[m.group(0)], v) if (rx and isinstance(v, str)) else v

    def val(kind, v):
        return maps[kind].get(v, v) if isinstance(v, str) else v

    out = json.loads(json.dumps(data))  # a private copy; the caller's structure is not modified
    held = ("The recorder counted calls it intercepted but did not record; the verifier's detail is withheld "
            "under --redact because it embeds a name.")
    for sec in (out["overall"], out["chain"]):
        sec["detail"] = held if sec.get("status") == "UNRECORDED_CALLS" else text(sec.get("detail", ""))
    for key in ("anchors", "witness"):
        sec = out[key]
        if "detail" in sec:
            sec["detail"] = text(sec["detail"])
        for row in sec.get("rows", []):
            if row.get("sink_ref") is not None:
                row["sink_ref"] = "(withheld)"
    hb = out["heartbeats"]
    if "detail" in hb:
        hb["detail"] = held if hb.get("status") == "UNRECORDED_CALLS" else text(hb["detail"])
    if "recorders" in hb:
        hb["recorders"] = sorted(val("recorder", x) for x in hb["recorders"])
        hb["tool_lists"] = sorted(val("tool", x) for x in hb["tool_lists"])
        hb["tool_changes"] = [{**c, "added": [val("tool", x) for x in c["added"]],
                               "removed": [val("tool", x) for x in c["removed"]]} for c in hb["tool_changes"]]
    rf = out["refusals"]
    if rf.get("by_tool") is not None:
        rf["by_tool"] = {val("tool", k): v for k, v in rf["by_tool"].items()}
        rf["by_agent"] = {val("agent", k): v for k, v in rf["by_agent"].items()}
    a2a = out["a2a"]
    if "detail" in a2a:
        a2a["detail"] = text(a2a["detail"])
        a2a["peers"] = [{**pr, "name": f"(peer ledger {i}: name withheld)"} for i, pr in enumerate(a2a.get("peers", []), 1)]
        a2a["findings"] = [{**f, "agent_id": val("agent", f.get("agent_id")), "peer": val("agent", f.get("peer")),
                            "ledger": "(name withheld)"} for f in a2a["findings"]]
    for i in out["inputs"]:
        i["name"] = f"({i['role']}: name withheld)"
    return out


# --------------------------------------------------------------------------------------------- document model
def _doc(data: dict) -> tuple[list, list]:
    """Return (blocks before the fixed section, blocks of the fixed section). A block is a tuple."""
    B: list = []
    o = data["overall"]
    empty_ok = data.get("scope") is not None and data["scope"].get("records") == 0

    def ex_of(status):
        e = explain(status)
        if empty_ok and status == "OK":
            e = {**e, "means": "The ledger held no records, so no check had anything to examine."}
        return e

    ex = ex_of(o["status"])
    B.append(("h1", "auditrail verification report"))
    unmasked = " It was NOT masked by --redact." if data.get("redacted") else ""
    if data.get("title"):
        B.append(("p", f"Title (supplied by whoever generated this report; not examined): {data['title']}.{unmasked}"))
    if data.get("note"):
        B.append(("p", f"Note (supplied by whoever generated this report; not examined): {data['note']}.{unmasked}"))
    if data.get("redacted"):
        salted = (data.get("redaction") or {}).get("salted")
        B.append(("p", "Names of agents, tools and recorders in this report have been masked by codes. The codes are not "
                       "secrets: " + ("they were mixed with a salt that was supplied when the report was made, but a "
                                      "name that is easy to guess can still be recovered by anyone who holds the salt "
                                      "or can try it." if salted else
                                      "no salt was supplied, so a low-entropy name can be recovered by guessing it and "
                                      "computing the same code.")))
        B.append(("p", f"Not masked: {REDACTION_NOT_MASKED}. The title and the note above are not masked either."))
    B.append(("p", f"Report fingerprint (sha256 of the body, excluding the timestamp line): {data['fingerprint_sha256']}"))
    B.append(("p", f"Generated: {data['generated_at'] or 'not stamped (pass --generated-at to add a timestamp)'}"))

    # 1 Result
    B.append(("h2", "1. Result"))
    empty = data.get("scope") is not None and data["scope"].get("records") == 0
    if o["status"] == "OK" and empty:
        B.append(("p", "The ledger holds no records. Nothing was examined, and this is not a statement about "
                       "anything that may have happened."))
    elif o["status"] == "OK" and not data.get("checks_ran"):
        B.append(("p", "No check ran over any record, so no statement is made about them."))
    elif o["status"] == "OK":
        B.append(("p", "The checks listed under 'Checks that ran' found no inconsistency in the records they covered."))
    elif ex["cls"] == "inconclusive":
        B.append(("p", f"No definite finding was made, but the examination is incomplete: {o['status']} "
                       f"({ex['label']}). This is not a consistent result."))
    else:
        at = f" at seq {o['bad_seq']}" if o.get("bad_seq") is not None else ""
        B.append(("p", f"A finding was made: {o['status']}{at} ({ex['label']})."))
    B.append(("p", f"Verifier status: {o['status']}. {ex['means']}"))
    if o.get("detail"):
        B.append(("p", f"Verifier's original wording: {o['detail']}"))
    B.append(("p", "This report is not signed and can be edited after it was made. Its fingerprint is a hash that makes "
                   "two copies easy to compare; it does not vouch for the content and is not a seal."))
    B.append(("p", "If the recorder's host or key was compromised, or the witness is not independent of the operator, "
                   "none of the above holds (see section 10)."))
    B.append(("p", "What this does not cover: " + ex["not_means"]))
    B.append(("p", "This report covers only tool calls that went through the recorder's wrapped tools. The tool list "
                   "shown under 'Heartbeats' is what the recorder reports as wrapped, not a statement of what the "
                   "agent can do. An action by a tool that was not wrapped leaves no record, and this report cannot "
                   "see it."))
    cov = data.get("coverage")
    if cov is not None and cov["unanchored_tail"]:
        rng = f"Records {cov['tail_first_seq']} to {cov['tail_last_seq']} ({cov['unanchored_tail']} record(s))"
        if cov["anchored_upto"] is None:
            B.append(("p", f"{rng}: no anchor was given (or the file held none), so no record is covered by an "
                           "anchor. Removal or rewriting of records cannot be detected by anchors; without keys, or "
                           "with only a witness copy, the result for them is OK with a note."))
        else:
            B.append(("p", f"{rng} come after the last anchor held by a witness. Changes in that range cannot be "
                           "detected by anchors; without keys, or with only a witness copy, the result for them is "
                           "OK with a note."))
    B.append(("h3", "Checks that ran"))
    ran = list(data.get("checks_ran") or []) or ["No check ran over any record."]
    B.append(("ul", ran))
    B.append(("h3", "Not checked"))
    B.append(("ul", data["not_checked"] or ["Nothing further was requested. The limits of the checks "
                                            "themselves are in section 10."]))

    # 2 Examined
    B.append(("h2", "2. What was examined"))
    B.append(("table", ["Role", "File", "SHA-256", "Bytes"],
              [[i["role"], i["name"], i["sha256"], str(i["bytes"])] for i in data["inputs"]]))
    B.append(("p", f"auditrail version {data['auditrail_version']}, report format {data['report_version']}."))
    sc = data.get("scope")
    if sc is None:
        pre = data.get("verified_prefix")
        B.append(("p", "The records failed an earlier check, so nothing computed from them is stated as fact. "
                       + (f"Records before seq {pre} are consistent with each other." if pre else
                          "No record is stated to be consistent.")))
    elif sc["records"]:
        B.append(("table", ["Records", "First seq", "Last seq", "First timestamp", "Last timestamp"],
                  [[str(sc["records"]), str(sc["first_seq"]), str(sc["last_seq"]), str(sc["first_ts"]), str(sc["last_ts"])]]))
        B.append(("table", ["Kind", "Count"], [[k, str(v)] for k, v in sorted(sc["kinds"].items())]))
    else:
        B.append(("p", "The ledger holds no records."))

    # 3 Keys
    B.append(("h2", "3. Keys"))
    if data["keys"]:
        B.append(("table", ["Key id", "SHA-256 of the public key", "Algorithm"],
                  [[k["key_id"], k["fingerprint_sha256"], k["algorithm"]] for k in data["keys"]]))
        B.append(("p", "Every record had to be signed by one of these keys. 'Trusted' means the keys the operator "
                       "supplied; this tool does not confirm where they came from."))
    else:
        B.append(("p", "No trusted key was given, so signatures were not checked."))
    if data.get("record_key_ids") is not None:
        B.append(("p", f"Key ids named by the records: {', '.join(data['record_key_ids']) or 'none'}. "
                       f"Signature algorithms named: {', '.join(data.get('record_algorithms') or []) or 'none'}."))

    # 4 Outcome per check
    B.append(("h2", "4. Verification outcome"))
    rows = []
    c = data["chain"]
    rows.append(["Hash chain, signatures and field rules" if data["signatures_required"]
                 else "Hash chain and field rules (signatures not checked: no key given)",
                 "ran" if data["chain"]["state"] not in ("unreadable", "legacy") and
                 (data.get("scope") or {}).get("records", 1) != 0 else "did not run",
                 c["status"], ex_of(c["status"])["means"]])
    for name, sec in (("Owner's anchors file", data["anchors"]), ("Witness copy", data["witness"])):
        if not sec.get("given"):
            rows.append([name, "not given", "-", "Not examined."])
        elif not sec.get("evaluated"):
            rows.append([name, "not evaluated", "-", "The records failed an earlier check; these lines cannot be relied on."])
        elif sec.get("lines", 0) == 0 and sec["status"] == "OK":
            rows.append([name, "empty: nothing compared", "-", "The file holds no anchors, so no comparison was made."])
        else:
            rows.append([name, "ran", sec["status"], ex_of(sec["status"])["means"]])
    hb = data["heartbeats"]
    if hb.get("status"):
        rows.append(["Heartbeats", "ran", hb["status"], ex_of(hb["status"])["means"] if hb["status"] != "OK"
                     else "No period longer than the limit without a heartbeat."])
    else:
        rows.append(["Heartbeats", "not checked" if hb.get("evaluated") else "not evaluated", "-",
                     "No gap limit was given." if hb.get("evaluated") else "The records failed an earlier check."])
    B.append(("table", ["Check", "State", "Status", "Meaning"], rows))
    B.append(("h3", "What each status means"))
    seen = sorted({r[2] for r in rows if r[2] not in ("-",)} | {o["status"]})
    B.append(("table", ["Status", "Class", "Meaning", "What it does not mean"],
              [[s, ex_of(s)["cls"], ex_of(s)["means"], ex_of(s)["not_means"]] for s in seen]))

    # 5 Witness
    B.append(("h2", "5. Witness and anchors"))
    any_anchor = False
    for name, sec in (("Owner's anchors file", data["anchors"]), ("Witness copy", data["witness"])):
        if not sec.get("given"):
            continue
        any_anchor = True
        if sec.get("evaluated") and sec.get("lines", 0) == 0:
            B.append(("p", f"{name}: the file holds no anchors, so nothing was compared against it. "
                           f"(Verifier status {sec['status']}.)"))
        elif sec.get("evaluated"):
            B.append(("p", f"{name}: {sec['lines']} line(s); status {sec['status']}. {sec.get('detail', '')}"))
            B.append(("table", ["Seq", "Created", "Key id", "Version", "Algorithm", "Published as"],
                      [[str(r["seq"]), str(r["created_at"]), str(r["key_id"]), str(r["version"]), str(r["sig_alg"]),
                        str(r["sink_ref"] or "")] for r in sec["rows"]]))
            if sec.get("rows_hidden"):
                B.append(("p", f"({sec['rows_hidden']} more line(s) not shown; counts above are complete.)"))
        else:
            B.append(("p", f"{name}: {sec['lines']} line(s) present but not evaluated."))
    if not any_anchor:
        B.append(("p", "No anchors file and no witness copy were given."))
    elif data["witness"].get("given") is False and data["anchors"].get("given"):
        B.append(("p", "Only the owner's anchors file was given. A witness copy held outside the owner's control "
                       "is what makes an anchor mean something."))
    if cov is not None:
        B.append(("p", f"Highest anchored seq: {cov['anchored_upto'] if cov['anchored_upto'] is not None else 'none'}. "
                       f"Records after it: {cov['unanchored_tail']}."))

    # 6 Heartbeats
    B.append(("h2", "6. Heartbeats"))
    if not hb.get("evaluated"):
        B.append(("p", "Not evaluated: the records failed an earlier check."))
    else:
        B.append(("p", f"{hb['count']} heartbeat record(s) from recorder(s): {', '.join(hb['recorders']) or 'none'}. "
                       f"Calls intercepted: {hb['calls_attempted']}; calls recorded: {hb['calls_recorded']}."))
        B.append(("p", "The tool list the recorder reports as wrapped: " + (", ".join(hb["tool_lists"]) or "none reported") +
                       ". An action by a tool that was not wrapped leaves no record, and this report cannot see it."
                       + ("" if hb["count"] else " No heartbeat was recorded, so even the list of wrapped tools is unknown.")))
        if hb.get("status") is None:
            B.append(("p", "No gap limit was given, so silent periods were not checked."))
        elif hb["status"] == "OK":
            B.append(("p", f"No period longer than {hb['max_gap_s']} seconds without a heartbeat."))
        else:
            B.append(("p", f"{hb['status']}: {hb['detail']}"))
            if hb.get("gaps"):
                gaps = hb["gaps"][:data["max_rows"]]
                B.append(("table", ["From", "To", "Seconds"], [[g["from"], g["to"], str(g["seconds"])] for g in gaps]))
        if hb["tool_changes"]:
            B.append(("table", ["Seq", "Timestamp", "Tools added", "Tools removed"],
                      [[str(c["seq"]), c["ts"], ", ".join(c["added"]), ", ".join(c["removed"])]
                       for c in hb["tool_changes"][:data["max_rows"]]]))

    # 7 Policy
    B.append(("h2", "7. Policy in force over time"))
    pol = data["policy"]
    if not pol["evaluated"]:
        B.append(("p", "Not evaluated: the records failed an earlier check."))
    elif pol["runs"]:
        B.append(("table", ["Policy hash", "Version", "First seq", "Last seq", "First timestamp", "Last timestamp"],
                  [[r["policy_hash"], str(r["policy_version"]), str(r["first_seq"]), str(r["last_seq"]), r["first_ts"], r["last_ts"]]
                   for r in pol["runs"][:data["max_rows"]]]))
    else:
        B.append(("p", "No call record carries a policy hash."))

    # 8 Refusals
    B.append(("h2", "8. Decisions and refusals"))
    rf = data["refusals"]
    if not rf["evaluated"]:
        B.append(("p", "Not evaluated: the records failed an earlier check."))
    else:
        B.append(("table", ["Decision", "Count"], [[k, str(v)] for k, v in sorted(rf["decisions"].items())]))
        if rf["by_class"]:
            B.append(("h3", "Refusals and errors by reason"))
            B.append(("table", ["Reason class", "Count"], [[k, str(v)] for k, v in sorted(rf["by_class"].items())]))
            rows_t = sorted(rf["by_tool"].items(), key=lambda kv: (-kv[1], kv[0]))
            B.append(("table", ["Tool", "Refusals or errors"], [[k, str(v)] for k, v in rows_t[:data["max_rows"]]]))
            if len(rows_t) > data["max_rows"]:
                B.append(("p", f"({len(rows_t) - data['max_rows']} more tool(s) not shown; counts above are complete.)"))
            rows_a = sorted(rf["by_agent"].items(), key=lambda kv: (-kv[1], kv[0]))
            B.append(("table", ["Agent", "Refusals or errors"], [[k, str(v)] for k, v in rows_a[:data["max_rows"]]]))

    # 9 A2A
    B.append(("h2", "9. Agent-to-agent messages"))
    a = data["a2a"]
    if not a.get("given"):
        recs = a.get("a2a_records_in_this_ledger") or {}
        B.append(("p", "Not examined: no peer ledgers were given, so messages could not be matched against the other "
                       "side. " + (("This ledger holds: " + ", ".join(f"{k}={v}" for k, v in sorted(recs.items())) + ".")
                                   if recs else "This ledger holds no agent-to-agent records.")))
    elif not a.get("evaluated"):
        B.append(("p", "Not evaluated: the records failed an earlier check."))
    else:
        B.append(("p", f"Status {a['status']}: {a['detail']}"))
        for i, pr in enumerate(a.get("peers", []), 1):
            B.append(("p", f"Peer ledger {i} ({pr['name']}): {pr['records'] if pr['records'] is not None else 'unreadable'} "
                           f"record(s), signing key id(s): {', '.join(pr['key_ids']) or 'none'}; signatures "
                           + ("checked against the trusted keys given." if pr["signatures_checked"]
                              else "were not checked (no public key was given).")
                           + (" Same signing key as the ledger: this does not show the other side is independent."
                              if pr["same_key"] else "")))
        if a.get("peer_same_as_ledger"):
            B.append(("p", f"{a['peer_same_as_ledger']} peer ledger(s) given have the same content as the ledger itself; "
                           "they were not an independent record of the other side."))
        if not (a.get("matched") or a["findings"] or a.get("findings_hidden")):
            B.append(("p", "No message was matched against another party's record."))
        if a.get("unverifiable"):
            B.append(("p", f"{a['unverifiable']} message(s) could not be compared because the other side's ledger "
                           "was not supplied."))
        if a["findings"]:
            fr = [[f["type"], f.get("agent_id") or "", f.get("peer") or "", str(f.get("seq")), f.get("ledger", "")]
                  for f in a["findings"]]
            B.append(("table", ["Finding", "Agent", "Peer", "Seq", "Ledger"], fr))
            if a.get("findings_hidden"):
                B.append(("p", f"({a['findings_hidden']} more finding(s) not shown.)"))

    # fixed section
    F: list = []
    F.append(("h2", "10. What this report does not prove"))
    F.append(("p", "This section is fixed. It is printed in every format and under every option."))
    F.append(("ul", list(LIMITS_FLOOR)))
    sha, items = _limits()
    groups: dict[str, list[str]] = {}
    for group, lead in items:
        groups.setdefault(group, []).append(lead)
    for group, leads in groups.items():
        F.append(("h3", group))
        F.append(("ul", leads))
    F.append(("p", f"Source of the list above: SECURITY.md (sha256 {sha}). Read it for the conditions attached to "
                   "each statement. The generated list records the file's hash only; which commit or date it came "
                   "from is not recorded. The lines above are quotations; words in them about certification or "
                   "compliance appear only in negations."))
    return B, F


# --------------------------------------------------------------------------------------------- renderers
def _clean(s: Any) -> str:
    """One line of printable text: every control, format, separator and unassigned character (newlines, U+2028,
    U+0085, bidi overrides, zero-width marks) becomes a space, and runs of spaces collapse. Free text from the
    evidence or from the person who generated the report can therefore not start a line of its own."""
    out = [" " if (unicodedata.category(ch)[0] in "CZ" or ch.isspace()) else ch for ch in str(s)]
    return re.sub(" {2,}", " ", "".join(out)).strip()


_MD_SPECIAL = re.compile(r"[\`*\[\]()!#|~]")
_MD_LEAD = re.compile(r"^(?:[-+=]|\d+[.)])(?=\s|$)")


def _md_text(s: Any) -> str:
    """Markdown-safe text: cleaned to one line, '<>&' as entities, and every Markdown metacharacter backslash-escaped
    ('_' only where it could open emphasis, i.e. not between two letters or digits)."""
    t = html.escape(_clean(s), quote=False)
    t = _MD_SPECIAL.sub(lambda m: "\\" + m.group(0), t)
    t = re.sub(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])", lambda m: "\\_", t)
    return _MD_LEAD.sub(lambda m: "\\" + m.group(0), t)


def _md_cell(s: Any) -> str:
    return _md_text(s)


def _md_heading(s: Any) -> str:
    return html.escape(_clean(s), quote=False)


def render_md(data: dict) -> str:
    B, F = _doc(data)
    out: list[str] = []
    for blk in B + F:
        t = blk[0]
        if t == "h1":
            out.append(f"# {_md_heading(blk[1])}\n")
        elif t == "h2":
            out.append(f"\n## {_md_heading(blk[1])}\n")
        elif t == "h3":
            out.append(f"\n### {_md_heading(blk[1])}\n")
        elif t == "p":
            if blk[1]:
                out.append(f"{_md_text(blk[1])}\n")
        elif t == "ul":
            out.extend(f"- {_md_text(i)}" for i in blk[1])
            out.append("")
        elif t == "table":
            out.append("| " + " | ".join(_md_cell(h) for h in blk[1]) + " |")
            out.append("|" + "|".join("---" for _ in blk[1]) + "|")
            out.extend("| " + " | ".join(_md_cell(c) for c in row) + " |" for row in blk[2])
            out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


_CSS = ("body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;"
        "line-height:1.5;color:#1a1a1a;background:#fff}table{border-collapse:collapse;margin:.5rem 0 1rem;width:100%}"
        "th,td{border:1px solid #bbb;padding:.3rem .5rem;text-align:left;vertical-align:top;font-size:.9rem;"
        "overflow-wrap:anywhere}th{background:#f0f0f0}h2{border-bottom:1px solid #ccc;padding-bottom:.2rem}"
        "@media (prefers-color-scheme:dark){body{background:#161616;color:#e8e8e8}th{background:#262626}"
        "th,td{border-color:#555}h2{border-color:#555}}")


def render_html(data: dict) -> str:
    B, F = _doc(data)
    e = lambda s: html.escape(_clean(s), quote=True)  # noqa: E731
    parts = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             "<title>auditrail verification report</title>", f"<style>{_CSS}</style></head><body>"]
    for blk in B + F:
        t = blk[0]
        if t in ("h1", "h2", "h3"):
            parts.append(f"<{t}>{e(blk[1])}</{t}>")
        elif t == "p":
            if blk[1]:
                parts.append(f"<p>{e(blk[1])}</p>")
        elif t == "ul":
            parts.append("<ul>" + "".join(f"<li>{e(i)}</li>" for i in blk[1]) + "</ul>")
        elif t == "table":
            parts.append("<table><thead><tr>" + "".join(f"<th>{e(h)}</th>" for h in blk[1]) + "</tr></thead><tbody>")
            parts.extend("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in blk[2])
            parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def render_json(data: dict) -> str:
    B, F = _doc(data)
    sha, items = _limits()
    payload = dict(data)
    payload["does_not_prove"] = {"heading": "What this report does not prove", "floor": list(LIMITS_FLOOR),
                                 "from_security_md": [{"group": g, "statement": s} for g, s in items],
                                 "security_md_sha256": sha}
    payload["status_explanations"] = {s: explain(s) for s in sorted(STATUS_TABLE)}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def limits_section_start_marker() -> str:
    return "## 10. What this report does not prove"
