"""Command-line entry point: `auditrail`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ledger import Ledger
from .policy import PolicyEngine


def _sinks(git_repo: str | None) -> dict:
    from .anchor import GitSink

    return {"git": GitSink(git_repo)} if git_repo else {}


def cmd_verify(args: argparse.Namespace) -> int:
    if not Path(args.ledger_path).is_file():
        print(f"[ERROR] {args.ledger_path}: file not found (nothing to verify)")
        return 2
    if args.anchors:
        from .anchor import verify_anchors

        result = verify_anchors(args.ledger_path, args.anchors, sinks=_sinks(args.git_repo))
        print(f"[{result['status']}] {result['detail']}")
        if result["anchored_upto"] is not None:
            print(f"  anchored up to seq={result['anchored_upto']}")
        for key in ("bad_seq", "max_seq", "line"):
            if key in result:
                print(f"  {key}={result[key]}")
        return 0 if result["status"] == "OK" else 1
    ledger = Ledger(args.ledger_path)
    ok, bad_seq = ledger.verify()
    count = sum(1 for _ in ledger)
    if ok:
        print(f"[OK] {args.ledger_path}: {count} records, hash chain intact.")
        return 0
    print(f"[TAMPER DETECTED] {args.ledger_path}: chain breaks at seq={bad_seq}.")
    print("Records before that point are verified genuine; records at/after it cannot be trusted.")
    return 1


def cmd_anchor(args: argparse.Namespace) -> int:
    from .anchor import AnchorError, SinkUnreachable, anchor_ledger

    if not Path(args.ledger).is_file():
        print(f"[ERROR] {args.ledger}: file not found (nothing to anchor)")
        return 2
    if args.push and not args.git_repo:
        print("[ERROR] --push requires --git-repo")
        return 2
    sink = _sinks(args.git_repo).get("git")
    try:
        result = anchor_ledger(Ledger(args.ledger), args.anchors, sink=sink, push=args.push)
    except AnchorError as exc:
        print(f"[REFUSED] {exc}")
        return 1
    except SinkUnreachable as exc:
        print(f"[SINK_UNREACHABLE] {exc}. No anchor was recorded.")
        return 1
    anchor = result["anchor"]
    if result["status"] == "UNCHANGED":
        print(f"[UNCHANGED] chain head is already anchored at seq={anchor['seq']}; nothing added.")
    else:
        ref = anchor["sink_ref"] or "none (local only; not externally witnessed)"
        print(f"[ANCHORED] seq={anchor['seq']} head={anchor['head_hash'][:12]} sink_ref={ref}")
    return 0


def cmd_policy_lint(args: argparse.Namespace) -> int:
    try:
        engine = PolicyEngine.from_yaml(args.policy_path)
    except Exception as exc:  # noqa: BLE001
        print(f"[INVALID] {args.policy_path}: {exc}")
        return 1
    n_agents = len(engine.agents)
    print(f"[OK] {args.policy_path}: version={engine.version!r}, {n_agents} agent(s) configured.")
    for agent_id, cfg in engine.agents.items():
        tools = cfg.get("allowed_tools", [])
        trifecta = cfg.get("enforce_lethal_trifecta", True)
        print(f"  - {agent_id}: {len(tools)} allow-listed tool(s), lethal-trifecta enforcement={trifecta}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from ._demo import run_demo  # self-contained: works after `pip install auditrail` too

    return run_demo()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditrail", description="Tamper-evident audit trails for AI agents.")
    sub = p.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="Verify a ledger file's hash chain has not been tampered with.")
    p_verify.add_argument("ledger_path")
    p_verify.add_argument("--anchors", help="Also verify against an anchors.jsonl file (protocol §6).")
    p_verify.add_argument("--git-repo", help="Git witness repo to check anchors against (with --anchors).")
    p_verify.set_defaults(func=cmd_verify)

    p_anchor = sub.add_parser("anchor", help="Record the current ledger head as an anchor, optionally publish it to a git witness.")
    p_anchor.add_argument("--ledger", required=True)
    p_anchor.add_argument("--anchors", required=True)
    p_anchor.add_argument("--git-repo", help="Git witness repository.")
    p_anchor.add_argument("--push", action="store_true", help="Also push the witness commit (explicit opt-in).")
    p_anchor.set_defaults(func=cmd_anchor)

    p_lint = sub.add_parser("lint", help="Validate a policy YAML file.")
    p_lint.add_argument("policy_path")
    p_lint.set_defaults(func=cmd_policy_lint)

    p_demo = sub.add_parser("demo", help="Run the offline demo (no API key needed): allow, deny, trifecta-block, tamper-detect.")
    p_demo.set_defaults(func=cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
