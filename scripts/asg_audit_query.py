#!/usr/bin/env python3
"""Metadata-only view of ASG audit events, per run or time window (no content, no tokens).

  python scripts/asg_audit_query.py --audit ~/.agent-security-gateway/audit.jsonl --run fcw-...
  python scripts/asg_audit_query.py --audit ... --since 2026-10-23T14:00 --prefix fcw-

Prints: time, run_id, event, decision/reason, route, agent, artifact status, finding categories, risk."""
import argparse
import json
from pathlib import Path


def cats(scan):
    return [f.get("category") for f in (scan or {}).get("findings") or []][:8]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", required=True)
    ap.add_argument("--run")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--since", default="")
    a = ap.parse_args()
    for line in Path(a.audit).expanduser().open(encoding="utf-8", errors="replace"):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        ts = str(e.get("ts") or e.get("timestamp") or "")
        run = str(e.get("run_id") or "")
        if a.run and a.run not in line:
            continue
        if a.prefix and not run.startswith(a.prefix):
            continue
        if a.since and ts and ts < a.since:
            continue
        scan = e.get("scan") or {}
        out = e.get("output_scan") or e.get("artifact_scan") or {}
        print(ts, run or "-", e.get("event"), e.get("decision") or e.get("reason"), e.get("route_id"),
              e.get("agent_id"), e.get("artifact_status") or "", cats(scan) + cats(out),
              scan.get("risk_score", out.get("risk_score", "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
