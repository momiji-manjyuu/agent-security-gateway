#!/usr/bin/env python3
"""Generate a caller token and SHA-256 hash for Agent Security Gateway."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an Agent Security Gateway token.")
    parser.add_argument("--bytes", type=int, default=32)
    args = parser.parse_args()
    if args.bytes < 16:
        raise SystemExit("--bytes must be at least 16")
    print(json.dumps(gateway.generate_agent_token(args.bytes), ensure_ascii=False, indent=2, sort_keys=True))
    print("Do not put the raw token in config. Store only token_sha256 there.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
