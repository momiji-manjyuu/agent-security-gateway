#!/bin/zsh
set -euo pipefail

LABEL="com.user.agent-security-gateway"
CONFIG_PATH="${ASG_CONFIG:-$HOME/.agent-security-gateway/config.json}"
PYTHON_BIN="${ASG_PYTHON:-python3}"
BASE_URL="$("$PYTHON_BIN" - "$CONFIG_PATH" <<'PY'
import json
import sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).expanduser().read_text(encoding="utf-8"))
print(f"http://{cfg['bind']}:{cfg['port']}")
PY
)"

launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && echo "launchd=loaded" || echo "launchd=not-loaded"
curl --noproxy '*' -fsS "$BASE_URL/healthz"
echo
