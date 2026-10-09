"""Cross-check agent-to-agent messages between two or more ledgers.

Each side of a v2 message writes its own record: the sender an `a2a_send`, the
receiver an `a2a_recv` (holding the sender's signature over the envelope), and
the sender an `a2a_ack` once it checks the receiver's signed receipt. All of
them carry the same msg_digest. Comparing ledgers then shows where the story
differs:

  RECV_WITHOUT_SEND  the receiver holds a message the sender's ledger never
                     recorded -- the sender bypassed its recorder, or its
                     ledger lost the record. The receiver's copy of the
                     sender's signature is the evidence.
  ACK_WITHOUT_RECV   the sender holds the receiver's signed receipt, but the
                     receiver's ledger has no matching a2a_recv.
  SEND_WITHOUT_RECV  the sender recorded a send the receiver never recorded
                     (lost in transit, rejected, or omitted by the receiver).

Only agents whose ledger was supplied are judged (those appearing in the ledgers, plus any
declared with agents=); a message to or from any other agent is counted as unverifiable,
not as a finding.
This proves both sides recorded the same message. It does not prove the
message's content was safe.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .verifier import check_chain, _read_records


def reconcile(ledger_paths, public_keys: Optional[dict[str, str]] = None, agents=()) -> dict:
    """agents: agent ids whose ledgers are among ledger_paths. Needed when one of those ledgers has
    no records at all (an agent that bypassed its recorder leaves nothing to infer its identity from)."""
    sends: dict[str, dict] = {}
    recvs: dict[str, dict] = {}
    acks: dict[str, dict] = {}
    rejected: list[dict] = []
    agents_by_ledger: dict[str, set] = {}

    for p in ledger_paths:
        path = Path(p)
        records, problem = _read_records(path)
        problem = problem or check_chain(path, public_keys=public_keys, records=records)
        if problem is not None:
            return {"status": problem["status"], "detail": f"{path.name}: {problem['detail']}", "ledger": str(path)}
        seen_agents = agents_by_ledger.setdefault(str(path), set())
        for r in records:
            if r.get("agent_id"):
                seen_agents.add(r["agent_id"])
            kind = r.get("kind")
            where = {"ledger": path.name, "seq": r["seq"], "agent_id": r.get("agent_id"), "peer": r.get("peer"),
                     "msg_id": r.get("msg_id")}
            if kind == "a2a_send":
                sends[r["msg_digest"]] = where
            elif kind == "a2a_recv" and r.get("status") == "accepted":
                recvs[r["msg_digest"]] = where
            elif kind == "a2a_recv":
                rejected.append({**where, "reason": r.get("reason")})
            elif kind == "a2a_ack":
                acks[r["msg_digest"]] = where

    known = (set().union(*agents_by_ledger.values()) if agents_by_ledger else set()) | set(agents)
    findings: list[dict] = []
    unverifiable = 0

    for digest, rv in recvs.items():
        if digest not in sends:
            if rv["peer"] in known:
                findings.append({"type": "RECV_WITHOUT_SEND", "msg_digest": digest, **rv})
            else:
                unverifiable += 1
    for digest, ak in acks.items():
        if digest not in recvs:
            if ak["peer"] in known:
                findings.append({"type": "ACK_WITHOUT_RECV", "msg_digest": digest, **ak})
            else:
                unverifiable += 1
    for digest, sd in sends.items():
        if digest not in recvs:
            if sd["peer"] in known:
                findings.append({"type": "SEND_WITHOUT_RECV", "msg_digest": digest, **sd})
            else:
                unverifiable += 1

    matched = sum(1 for d in sends if d in recvs)
    status = "OK" if not findings else "MISMATCH"
    detail = (f"{matched} message(s) recorded by both sides; {len(findings)} mismatch(es); "
              f"{len(rejected)} rejected; {unverifiable} involve agents whose ledger was not supplied")
    return {"status": status, "detail": detail, "matched": matched, "findings": findings,
            "rejected": rejected, "unverifiable": unverifiable}
