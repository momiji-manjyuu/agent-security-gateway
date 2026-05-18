#!/usr/bin/env python3
"""Run a small red-team corpus against Agent Security Proxy scanners."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import proxy  # noqa: E402


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                case = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            case.setdefault("id", f"case-{line_number}")
            case.setdefault("direction", "input")
            case.setdefault("expect", "review_or_block")
            cases.append(case)
    return cases


def classify(case: dict[str, Any], cfg: dict[str, Any]) -> tuple[str, proxy.ScanResult]:
    text = str(case.get("text", ""))
    direction = str(case.get("direction", "input"))
    if direction == "output":
        scan = proxy.scan_output_text(text, cfg)
        if proxy.output_guard_blocks(scan, cfg):
            return "block", scan
        if scan.requires_review:
            return "review", scan
        return "allow", scan

    scan = proxy.scan_text(text, cfg)
    proxy.apply_llm_inspector(scan, cfg)
    if scan.blocked:
        return "block", scan
    if scan.requires_review:
        return "review", scan
    return "allow", scan


def expectation_met(decision: str, expected: str) -> bool:
    if expected == decision:
        return True
    if expected == "review_or_block" and decision in {"review", "block"}:
        return True
    if expected == "allow_or_review" and decision in {"allow", "review"}:
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the proxy scanners against a JSONL corpus.")
    parser.add_argument("--corpus", type=Path, default=ROOT / "tests" / "redteam_corpus.jsonl")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of a table.")
    args = parser.parse_args()

    cfg = proxy.load_config(args.config) if args.config else json.loads(json.dumps(proxy.DEFAULT_CONFIG))
    rows: list[dict[str, Any]] = []
    for case in load_cases(args.corpus):
        decision, scan = classify(case, cfg)
        expected = str(case.get("expect", "review_or_block"))
        rows.append(
            {
                "id": case["id"],
                "direction": case.get("direction", "input"),
                "expect": expected,
                "decision": decision,
                "ok": expectation_met(decision, expected),
                "risk_score": scan.risk_score,
                "findings": [finding.category for finding in scan.findings],
            }
        )

    passed = sum(1 for row in rows if row["ok"])
    failed = len(rows) - passed
    if args.json:
        print(json.dumps({"passed": passed, "failed": failed, "cases": rows}, ensure_ascii=False, indent=2))
    else:
        print(f"redteam corpus: {passed}/{len(rows)} passed")
        for row in rows:
            status = "ok" if row["ok"] else "FAIL"
            findings = ",".join(row["findings"]) or "-"
            print(
                f"{status:4} {row['id']:24} direction={row['direction']:6} "
                f"expect={row['expect']:15} decision={row['decision']:6} score={row['risk_score']:3} findings={findings}"
            )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
