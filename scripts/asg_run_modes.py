#!/usr/bin/env python3
"""Switch the opt-in run modes in an ASG config (with a timestamped backup), e.g.

  python scripts/asg_run_modes.py --config ~/.agent-security-gateway/config.json --test-mode off --quarantined-read off
  python scripts/asg_run_modes.py --config ... --show

Only flips `test_modes.input_guard_log_only.enabled` and `quarantined_read.enabled`; restart ASG afterwards.
Both modes stay off except during an explicitly approved test session (see docs/guides/test-modes.md)."""
import argparse
import json
import shutil
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--test-mode", choices=("on", "off"))
    ap.add_argument("--quarantined-read", choices=("on", "off"))
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()
    path = Path(a.config).expanduser()
    cfg = json.loads(path.read_text(encoding="utf-8"))
    tm = cfg.setdefault("test_modes", {}).setdefault("input_guard_log_only", {"enabled": False})
    qr = cfg.setdefault("quarantined_read", {"enabled": False})
    if not a.show and (a.test_mode or a.quarantined_read):
        shutil.copy2(path, str(path) + ".bak-modes-" + time.strftime("%Y%m%d%H%M%S"))
        if a.test_mode:
            tm["enabled"] = a.test_mode == "on"
        if a.quarantined_read:
            qr["enabled"] = a.quarantined_read == "on"
        path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(json.dumps({"test_mode": bool(tm.get("enabled")), "quarantined_read": bool(qr.get("enabled"))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
