"""The MVP demonstration, end to end, in a temporary directory.

    python -m examples.mvp_demo.run

simulated agent -> recorder signature -> anchor published to a witness copy -> one record deliberately altered ->
the verifier catches it -> `auditrail report` writes a readable account. Every step is an ordinary command (the
same ones the README lists); nothing here uses shell-specific syntax. Exit code 0 only if every step behaved as
expected.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

PY = sys.executable
CLI = [PY, "-m", "auditrail.cli"]
HERE = Path(__file__).resolve().parent

DISCLAIMER = (
    "Demonstration: the agent and the signing key are on the same machine here, so this shows the MECHANISM only.\n"
    "In a real deployment the recorder runs as a separate process or account (`auditrail recorder`) and the\n"
    "witness copy is kept somewhere the operator cannot rewrite."
)


def sh(args):
    r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return ((r.stdout or "") + (r.stderr or "")).strip(), r.returncode


def main() -> int:
    print(DISCLAIMER + "\n")
    failures: list = []

    def step(n, title, args, code=0, must_contain=(), show=2):
        out, rc = sh(args)
        ok = rc == code and all(needle in out for needle in must_contain)
        print(f"[{n}] {title}: {'ok' if ok else 'UNEXPECTED'} (exit {rc})")
        for line in out.splitlines()[:show]:
            print(f"      {line}")
        if not ok:
            failures.append(f"step {n}: {title}")
            print(f"      expected exit code {code} and {list(must_contain)}")
        return out

    with tempfile.TemporaryDirectory(prefix="auditrail-mvp-") as tmp:
        d = Path(tmp)
        key, pub = d / "recorder.key", d / "recorder.pub"
        ledger, anchors, witness = d / "ledger.jsonl", d / "anchors.jsonl", d / "witness.jsonl"
        tampered, rehashed = d / "ledger-tampered.jsonl", d / "ledger-rehashed.jsonl"
        keys = ["--pubkey", str(pub)]
        gap = ["--max-gap", "3600"]

        step(1, "create the recorder key", [*CLI, "keygen", "--out", str(d / "recorder")], must_contain=["recorder.pub"])
        step(2, "simulated agent calls tools (signed by the recorder key)",
             [PY, str(HERE / "agent.py"), "--key", str(key), "--out", str(ledger)], show=8, must_contain=["REFUSED"])
        step(3, "publish an anchor to the witness copy",
             [*CLI, "anchor", "--ledger", str(ledger), "--anchors", str(anchors), "--key", str(key),
              "--witness-file", str(witness)], must_contain=["[ANCHORED]"])
        step(4, "verify the original with only the public key and the witness copy",
             [*CLI, "verify", str(ledger), *keys, *gap, "--witness-file", str(witness)],
             must_contain=["[OK]"], show=4)
        step(5, "alter one recorded decision", [PY, str(HERE / "tamper.py"), str(ledger), str(tampered)],
             must_contain=["deny -> allow"])
        step(6, "verify the altered copy",
             [*CLI, "verify", str(tampered), *keys, *gap, "--witness-file", str(witness)], code=1,
             must_contain=["TAMPER DETECTED"], show=3)
        step("6b", "the cleverer attempt: alter AND recompute the whole hash chain",
             [PY, str(HERE / "tamper.py"), str(ledger), str(rehashed), "--rehash"], must_contain=["recomputed"])
        step("6c", "verify it with the key (the old signatures no longer match)",
             [*CLI, "verify", str(rehashed), *keys], code=1, must_contain=["BAD_SIGNATURE"], show=2)
        step("6d", "verify it with only the witness copy (no key)",
             [*CLI, "verify", str(rehashed), "--witness-file", str(witness)], code=1, must_contain=["REWRITTEN"], show=2)
        step(7, "report on the altered copy",
             [*CLI, "report", str(tampered), *keys, "--witness-file", str(witness), *gap, "--format", "all",
              "--out", str(d / "report-tampered")], code=1, must_contain=["report-tampered.md"], show=3)
        step(8, "report on the original",
             [*CLI, "report", str(ledger), *keys, "--witness-file", str(witness), *gap, "--format", "all",
              "--out", str(d / "report")], code=0, must_contain=["report.md"], show=3)

        for name, needle in (("report-tampered.md", "TAMPERED_LEDGER"), ("report.md", "no inconsistency")):
            text = (d / name).read_text(encoding="utf-8")
            ok = needle in text and "What this report does not prove" in text
            print(f"[9] {name} states {needle!r} and the fixed limits section: {'ok' if ok else 'UNEXPECTED'}")
            if not ok:
                failures.append(f"report content: {name}")
        print()
        print((d / "report.md").read_text(encoding="utf-8").split("## 2. What was examined")[0].rstrip())

    print()
    if failures:
        print("MVP demo: UNEXPECTED results in: " + "; ".join(failures))
        return 1
    print("MVP demo: every step behaved as expected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
