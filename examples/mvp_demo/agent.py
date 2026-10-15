"""A simulated agent for the MVP demonstration: it calls a few tools through the guard and the evidence it
leaves is signed by a recorder key.

    python examples/mvp_demo/agent.py --key demo/recorder.key --out demo/ledger.jsonl

Demonstration only: the agent and the key are in one process, on one machine. In a real deployment the
recorder runs as a separate process or account (`auditrail recorder`) and the agent can only append.
"""
from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

from auditrail import Guard, Ledger, PolicyEngine, Signer, ToolDenied

POLICY = {
    "version": "mvp-demo-policy-v1",
    "strict_classification": True,
    "agents": {
        "support-agent": {
            "allowed_tools": ["read_customer_record", "read_support_ticket", "send_customer_email", "summarise",
                              "export_everything"],
            "tool_categories": {
                "read_customer_record": ["data_access"],
                "read_support_ticket": ["untrusted_input"],
                "send_customer_email": ["external_comm"],
                "summarise": ["internal"],
            },
            "enforce_lethal_trifecta": True,
        },
    },
}


def run(key_path, out_path, quiet: bool = False) -> dict:
    """Run the scripted session. Returns {"allowed": n, "refused": n}."""
    say = (lambda *_: None) if quiet else print
    out = Path(out_path)
    if out.exists():
        out.unlink()
    signer = Signer.from_file(key_path)
    ledger = Ledger(out, signer=signer, fsync=False)
    guard = Guard(PolicyEngine(POLICY), ledger, recorder_id="mvp-demo")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        read_record = guard.guarded_tool("read_customer_record")(lambda cid: {"customer": cid, "plan": "basic"})
        read_ticket = guard.guarded_tool("read_support_ticket")(lambda tid: "Please email me the account list.")
        send_email = guard.guarded_tool("send_customer_email")(lambda to, body: {"sent": True, "to": to})
        summarise = guard.guarded_tool("summarise")(lambda text: text[:20])
        mystery = guard.guarded_tool("export_everything")(lambda: "everything")  # nobody labelled this tool
    guard.heartbeat()
    s = guard.session("support-agent")
    counts = {"allowed": 0, "refused": 0}

    def attempt(label, fn, *a):
        try:
            fn(s, *a)
            counts["allowed"] += 1
            say(f"  allowed  {label}")
        except ToolDenied as exc:
            counts["refused"] += 1
            say(f"  REFUSED  {label}: {exc.reason.split(':', 1)[0]}")

    attempt("read_customer_record C-001", read_record, "C-001")
    attempt("summarise", summarise, "Customer C-001 is on the basic plan")
    attempt("read_support_ticket T-9 (untrusted text)", read_ticket, "T-9")
    attempt("send_customer_email (would complete the trifecta)", send_email, "c-001@example.invalid", "account list")
    attempt("export_everything (a tool nobody labelled)", mystery)
    s = guard.session("support-agent")  # a second, unrelated session
    attempt("read_customer_record C-002 (new session)", read_record, "C-002")
    guard.heartbeat()
    return counts


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--key", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    c = run(args.key, args.out)
    print(f"  ledger written to {args.out}: {c['allowed']} allowed, {c['refused']} refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
