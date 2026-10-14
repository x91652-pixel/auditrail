"""Command-line entry point: `auditrail`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ledger import Ledger
from .policy import PolicyEngine


def _sinks(git_repo: str | None) -> dict:
    from .anchor import GitSink

    return {"git": GitSink(git_repo)} if git_repo else {}


def _keys(args: argparse.Namespace) -> dict | None:
    from .keys import load_public_keys

    return load_public_keys(args.pubkey) if getattr(args, "pubkey", None) else None


def cmd_verify(args: argparse.Namespace) -> int:
    from .verifier import verify_all

    if not Path(args.ledger_path).is_file():
        print(f"[ERROR] {args.ledger_path}: file not found (nothing to verify)")
        return 2
    if args.legacy_v01:
        from .verifier import verify_legacy_v01

        result = verify_legacy_v01(args.ledger_path)
    else:
        result = verify_all(
            args.ledger_path, public_keys=_keys(args), anchors_path=args.anchors, sinks=_sinks(args.git_repo),
            witness_path=args.witness_file, max_gap_s=args.max_gap,
        )
    code = 0 if result["status"] == "OK" else 1
    if args.json:
        result.setdefault("anchored_upto", None)
        result.setdefault("unanchored_tail", None)
        print(json.dumps(result, ensure_ascii=False))
        return code
    if result["status"] == "OK":
        print(f"[OK] {args.ledger_path}: {result['records']} records, hash chain intact.")
        if result.get("signatures_checked"):
            print("  all records signed by a trusted key")
        if result.get("anchored_upto") is not None:
            print(f"  anchored up to seq={result['anchored_upto']} ({result['unanchored_tail']} record(s) after it not covered)")
        for ch in result.get("changes", []):
            policy = f" policy changed to {ch['policy_version']}" if ch["policy_changed"] else ""
            print(f"  change at seq={ch['seq']} ({ch['ts']}): tools added {ch['tools_added']}, removed {ch['tools_removed']}{policy}")
        for note in result.get("notes", []):
            print(f"  note: {note}")
        return 0
    if result["status"] == "TAMPERED_LEDGER":
        print(f"[TAMPER DETECTED] {args.ledger_path}: chain breaks at seq={result.get('bad_seq')}.")
        print(f"  {result['detail']}")
        print("Records before that point are verified genuine; records at/after it cannot be trusted.")
        return 1
    print(f"[{result['status']}] {result['detail']}")
    for key in ("bad_seq", "max_seq", "line"):
        if key in result:
            print(f"  {key}={result[key]}")
    for gap in result.get("gaps", []):
        print(f"  no heartbeat from {gap['from']} to {gap['to']} ({gap['seconds']}s)")
    return code


def _anchor_fail(args: argparse.Namespace, status: str, detail: str, code: int) -> int:
    if args.json:
        print(json.dumps({"status": status, "detail": detail}, ensure_ascii=False))
    else:
        print(f"[{status}] {detail}")
    return code


def cmd_anchor(args: argparse.Namespace) -> int:
    from .anchor import AnchorError, SinkUnreachable, anchor_ledger

    if not Path(args.ledger).is_file():
        return _anchor_fail(args, "ERROR", f"{args.ledger}: file not found (nothing to anchor)", 2)
    if args.push and not args.git_repo:
        return _anchor_fail(args, "ERROR", "--push requires --git-repo", 2)
    sink = _sinks(args.git_repo).get("git")
    if sink is None and args.witness_file:
        from .anchor import FileSink

        sink = FileSink(args.witness_file)
    signer = None
    if args.key:
        from .keys import Signer

        signer = Signer.from_file(args.key)
    try:
        result = anchor_ledger(Ledger(args.ledger), args.anchors, sink=sink, push=args.push, signer=signer)
    except AnchorError as exc:
        return _anchor_fail(args, "REFUSED", str(exc), 1)
    except SinkUnreachable as exc:
        return _anchor_fail(args, "SINK_UNREACHABLE", f"{exc}. No anchor was recorded.", 1)
    anchor = result["anchor"]
    if args.json:
        print(json.dumps({"status": result["status"], "anchor": anchor}, ensure_ascii=False))
        return 0
    if result["status"] == "UNCHANGED":
        print(f"[UNCHANGED] chain head is already anchored at seq={anchor['seq']}; nothing added.")
    else:
        ref = anchor["sink_ref"] or "none (local only; not externally witnessed)"
        print(f"[ANCHORED] seq={anchor['seq']} head={anchor['head_hash'][:12]} sink_ref={ref}")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    from .keys import Signer

    signer = Signer.generate()
    try:
        key_path, pub_path = signer.save(args.out)
    except FileExistsError as exc:
        print(f"[REFUSED] {exc}")
        return 1
    print(f"[OK] key_id={signer.key_id}")
    print(f"  private key: {key_path}  (keep it where the agent process cannot read it)")
    print(f"  public key:  {pub_path}  (publish this; verifiers need it)")
    return 0


def cmd_recorder(args: argparse.Namespace) -> int:
    from .recorder import serve

    return serve(args)


def cmd_reconcile(args: argparse.Namespace) -> int:
    from .reconcile import reconcile

    missing = [p for p in args.ledgers if not Path(p).is_file()]
    if missing:
        print(f"[ERROR] file(s) not found: {', '.join(missing)}")
        return 2
    result = reconcile(args.ledgers, public_keys=_keys(args), agents=args.agent or ())
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        print(f"[{result['status']}] {result['detail']}")
        for f in result.get("findings", []):
            print(f"  {f['type']}: {f['ledger']} seq={f['seq']} {f['agent_id']} <-> {f['peer']} msg={f['msg_digest'][:12]}")
    return 0 if result["status"] == "OK" else 1


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

    p_verify = sub.add_parser("verify", help="Verify a ledger offline: chain, signatures, anchors, witness, heartbeats.")
    p_verify.add_argument("ledger_path")
    p_verify.add_argument("--pubkey", action="append", help="Trusted recorder public key (.pub). Repeatable. "
                          "When given, every record and anchor must be signed by one of these keys.")
    p_verify.add_argument("--anchors", help="Also verify against an anchors.jsonl file (protocol §6).")
    p_verify.add_argument("--git-repo", help="Git witness repo to check anchors against (with --anchors).")
    p_verify.add_argument("--witness-file", help="A copy of the anchor lines a witness holds; checked against the ledger "
                          "without trusting the owner's anchors file.")
    p_verify.add_argument("--max-gap", type=int, help="Fail if any period longer than this many seconds has no heartbeat.")
    p_verify.add_argument("--legacy-v01", action="store_true",
                          help="Check a v0.1 ledger (no `format` field): hash chain only, unsigned. Python only.")
    p_verify.add_argument("--json", action="store_true", help="Print the verification result as JSON.")
    p_verify.set_defaults(func=cmd_verify)

    p_anchor = sub.add_parser("anchor", help="Record the current ledger head as an anchor, optionally publish it to a git witness.")
    p_anchor.add_argument("--ledger", required=True)
    p_anchor.add_argument("--anchors", required=True)
    p_anchor.add_argument("--git-repo", help="Git witness repository.")
    p_anchor.add_argument("--push", action="store_true", help="Also push the witness commit (explicit opt-in).")
    p_anchor.add_argument("--witness-file", help="File witness (append the anchor line there), if no --git-repo.")
    p_anchor.add_argument("--key", help="Recorder private key: sign the anchor (anchor_version 2).")
    p_anchor.add_argument("--json", action="store_true", help="Print the result as JSON.")
    p_anchor.set_defaults(func=cmd_anchor)

    p_keygen = sub.add_parser("keygen", help="Create an Ed25519 key pair: <out>.key (private) and <out>.pub.")
    p_keygen.add_argument("--out", required=True, help="Path prefix, e.g. keys/recorder")
    p_keygen.set_defaults(func=cmd_keygen)

    p_rec = sub.add_parser("recorder", help="Run the recorder service: holds the ledger and key, agents can only append.")
    p_rec.add_argument("--ledger", required=True)
    p_rec.add_argument("--key", required=True, help="Recorder private key (.key)")
    p_rec.add_argument("--port", type=int, default=8765)
    p_rec.add_argument("--policy", help="Policy YAML, so heartbeats carry its version and hash.")
    p_rec.add_argument("--heartbeat", type=int, default=60, help="Seconds between heartbeats (0 = off).")
    p_rec.add_argument("--anchors", help="anchors.jsonl to append signed anchors to.")
    p_rec.add_argument("--anchor-every", type=int, default=None,
                       help="Seconds between anchors (default 300 when --anchors is given; 0 = only on clean shutdown, "
                       "which a kill or crash skips).")
    p_rec.add_argument("--witness-file", help="File witness for anchors.")
    p_rec.add_argument("--git-repo", help="Git witness for anchors (never pushed automatically).")
    p_rec.add_argument("--token-env", default="AUDITRAIL_RECORDER_TOKEN",
                       help="Environment variable holding the shared token agents must present.")
    p_rec.set_defaults(func=cmd_recorder)

    p_rc = sub.add_parser("reconcile", help="Cross-check agent-to-agent messages between ledgers.")
    p_rc.add_argument("ledgers", nargs="+")
    p_rc.add_argument("--pubkey", action="append", help="Trusted recorder public key(s); every record must be signed.")
    p_rc.add_argument("--agent", action="append", help="Agent id whose ledger is among those given (repeatable). "
                      "Use it when an agent's ledger may be empty.")
    p_rc.add_argument("--json", action="store_true")
    p_rc.set_defaults(func=cmd_reconcile)

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
