"""Alter one recorded decision, the way someone covering their tracks would.

    python examples/mvp_demo/tamper.py LEDGER OUT            # edit one record; the hashes are NOT recomputed
    python examples/mvp_demo/tamper.py LEDGER OUT --rehash   # edit it and recompute every hash after it

The first leaves a broken chain. The second leaves a consistent chain, but the old signatures no longer
match, and a witness copy of the original head no longer matches either.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from auditrail.ledger import GENESIS_HASH, _canonical, record_hash


def tamper(src, dst, rehash: bool = False) -> int:
    recs = [json.loads(x) for x in Path(src).read_text(encoding="utf-8").splitlines() if x.strip()]
    idx = next((i for i, r in enumerate(recs) if r.get("decision") == "deny"), None)
    if idx is None:
        raise SystemExit("no refused call found to alter")
    recs[idx]["decision"] = "allow"
    recs[idx]["reason"] = None
    if rehash:
        prev = GENESIS_HASH
        for r in recs:
            r["prev_hash"] = prev
            r["hash"] = record_hash(prev, r)
            prev = r["hash"]
    Path(dst).write_text("".join(_canonical(r) + "\n" for r in recs), encoding="utf-8", newline="\n")
    return idx


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("ledger")
    p.add_argument("out")
    p.add_argument("--rehash", action="store_true")
    a = p.parse_args(argv)
    idx = tamper(a.ledger, a.out, a.rehash)
    print(f"  changed seq {idx}: decision deny -> allow" + (" and recomputed the hash chain" if a.rehash else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
