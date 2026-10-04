"""Run the simulated logistics company: normal operations, then attacks.

    python -m examples.logistics_sim.run

Writes the evidence ledger to examples/logistics_sim/ledger.jsonl and
prints a report. Exit code is 0 only if every result matches its declared
expectation (including known gaps, which are expected to NOT be stopped).
"""
from __future__ import annotations

import sys
from pathlib import Path

from .scenarios import run_simulation

LEDGER = Path(__file__).resolve().parent / "ledger.jsonl"


def _row(cols, widths):
    return "  ".join(str(c).ljust(w) for c, w in zip(cols, widths))


def main() -> int:
    report = run_simulation(LEDGER)
    legit, attacks = report["legit"], report["attacks"]

    print("模擬物流公司（合成資料）— 正常營運\n")
    widths = (4, 58, 9)
    print(_row(["#", "情境", "結果"], widths))
    for i, r in enumerate(legit, 1):
        print(_row([i, r.name, r.actual], widths))
    false_positives = [r for r in legit if r.actual != "ALLOWED"]
    print(f"\n誤擋（應放行卻被擋）：{len(false_positives)} / {len(legit)}")

    print("\n模擬攻擊\n")
    widths = (4, 52, 14, 14, 7)
    print(_row(["#", "攻擊", "實際", "預期", "符合"], widths))
    for i, r in enumerate(attacks, 1):
        print(_row([i, r.name, r.actual, r.expected, "PASS" if r.passed else "FAIL"], widths))
        print(f"      技術：{r.technique}")
        if r.detail:
            print(f"      細節：{r.detail}")
        if r.owasp:
            print(f"      對應：{r.owasp}")
        if r.known_gap:
            print(f"      已知限制：{r.known_gap}")

    defended = sum(1 for r in attacks if r.expected in ("BLOCKED", "CONTAINED", "DETECTED"))
    gaps = [r for r in attacks if r.known_gap]
    print("\n摘要")
    print(f"  正常營運放行率：{len(legit) - len(false_positives)} / {len(legit)}")
    print(f"  攻擊防禦成功：{sum(1 for r in attacks if r.expected in ('BLOCKED','CONTAINED','DETECTED') and r.passed)} / {defended}")
    print(f"  已知未防禦（文件化的限制）：{len(gaps)} 項，實際未被攔截：{sum(1 for r in gaps if r.passed)} 項")
    print(f"  證據日誌：{report['record_count']} 筆，雜湊鏈完整：{report['ledger_ok']}")
    print(f"  決策統計：{report['decisions']}")
    print(f"  實際寄出的外部訊息：{report['outbox_count']} 則")
    print(f"  日誌位置：{report['ledger_path']}")

    failed = [r for r in legit + attacks if not r.passed]
    if failed:
        print(f"\n有 {len(failed)} 項結果與預期不符，請檢查。")
        return 1
    print("\n所有結果均符合預期。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
