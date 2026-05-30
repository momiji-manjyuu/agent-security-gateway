#!/usr/bin/env python3
"""Run a small red-team corpus against the gateway scanner stack."""

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
            tags = case.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            if not isinstance(tags, list):
                tags = []
            case["tags"] = [str(tag) for tag in tags]
            cases.append(case)
    return cases


def classify(case: dict[str, Any], cfg: dict[str, Any]) -> tuple[str, proxy.ScanResult]:
    direction = str(case.get("direction", "input"))
    capability = str(case.get("capability", "public_readonly_search"))
    if direction == "input" and isinstance(case.get("payload"), dict):
        scan = proxy.scan_inbound_payload(case["payload"], cfg).scan
        if scan.blocked:
            return "block", scan
        if scan.requires_review:
            return "review", scan
        return "allow", scan

    text = str(case.get("text", ""))
    if direction == "output":
        scan = proxy.scan_output_text(text, cfg, capability)
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
    parser = argparse.ArgumentParser(description="Evaluate the gateway scanners against a JSONL corpus.")
    parser.add_argument("--corpus", type=Path, default=ROOT / "tests" / "redteam_corpus.jsonl")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of a table.")
    args = parser.parse_args()

    cfg = proxy.load_config(args.config) if args.config else json.loads(json.dumps(proxy.DEFAULT_CONFIG))
    rows: list[dict[str, Any]] = []
    tag_metrics: dict[str, dict[str, int]] = {}
    counts: dict[str, int] = {
        "attack_total": 0,
        "attack_caught": 0,
        "benign_total": 0,
        "benign_allowed": 0,
    }
    for case in load_cases(args.corpus):
        decision, scan = classify(case, cfg)
        expected = str(case.get("expect", "review_or_block"))
        is_attack = expected in {"review", "block", "review_or_block"}
        if is_attack:
            counts["attack_total"] += 1
            if decision in {"review", "block"}:
                counts["attack_caught"] += 1
        else:
            counts["benign_total"] += 1
            if decision == "allow":
                counts["benign_allowed"] += 1
        ok = expectation_met(decision, expected)
        for tag in case.get("tags", []):
            tag_row = tag_metrics.setdefault(
                tag,
                {
                    "total": 0,
                    "passed": 0,
                    "attack_total": 0,
                    "attack_caught": 0,
                    "benign_total": 0,
                    "benign_allowed": 0,
                },
            )
            tag_row["total"] += 1
            if ok:
                tag_row["passed"] += 1
            if is_attack:
                tag_row["attack_total"] += 1
                if decision in {"review", "block"}:
                    tag_row["attack_caught"] += 1
            else:
                tag_row["benign_total"] += 1
                if decision == "allow":
                    tag_row["benign_allowed"] += 1
        rows.append(
            {
                "id": case["id"],
                "direction": case.get("direction", "input"),
                "capability": case.get("capability", "public_readonly_search"),
                "expect": expected,
                "decision": decision,
                "ok": ok,
                "tags": case.get("tags", []),
                "risk_score": scan.risk_score,
                "findings": [finding.category for finding in scan.findings],
            }
        )

    passed = sum(1 for row in rows if row["ok"])
    failed = len(rows) - passed
    metrics = {
        "attack_catch_rate": (counts["attack_caught"] / counts["attack_total"]) if counts["attack_total"] else None,
        "benign_allow_rate": (counts["benign_allowed"] / counts["benign_total"]) if counts["benign_total"] else None,
        **counts,
    }
    if args.json:
        print(
            json.dumps(
                {"passed": passed, "failed": failed, "metrics": metrics, "tag_metrics": tag_metrics, "cases": rows},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"redteam corpus: {passed}/{len(rows)} passed")
        if metrics["attack_catch_rate"] is not None:
            print(f"attack catch rate: {metrics['attack_caught']}/{metrics['attack_total']} = {metrics['attack_catch_rate']:.2%}")
        if metrics["benign_allow_rate"] is not None:
            print(f"benign allow rate: {metrics['benign_allowed']}/{metrics['benign_total']} = {metrics['benign_allow_rate']:.2%}")
        if tag_metrics:
            print("tag coverage:")
            for tag, tag_row in sorted(tag_metrics.items()):
                print(f"  {tag}: {tag_row['passed']}/{tag_row['total']} passed")
        for row in rows:
            status = "ok" if row["ok"] else "FAIL"
            findings = ",".join(row["findings"]) or "-"
            tags = ",".join(row["tags"]) or "-"
            print(
                f"{status:4} {row['id']:24} direction={row['direction']:6} "
                f"capability={row['capability']:22} expect={row['expect']:15} "
                f"decision={row['decision']:6} score={row['risk_score']:3} tags={tags} findings={findings}"
            )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
