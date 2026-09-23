"""Command-line entry point: `auditrail`."""
from __future__ import annotations

import argparse
import sys

from .ledger import Ledger
from .policy import PolicyEngine


def cmd_verify(args: argparse.Namespace) -> int:
    ledger = Ledger(args.ledger_path)
    ok, bad_seq = ledger.verify()
    count = sum(1 for _ in ledger)
    if ok:
        print(f"[OK] {args.ledger_path}: {count} records, hash chain intact.")
        return 0
    print(f"[TAMPER DETECTED] {args.ledger_path}: chain breaks at seq={bad_seq}.")
    print("Records before that point are verified genuine; records at/after it cannot be trusted.")
    return 1


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
    p_verify.set_defaults(func=cmd_verify)

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
