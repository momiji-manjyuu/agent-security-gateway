#!/bin/zsh
set -euo pipefail

LABEL="com.user.agent-security-gateway"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/launchd/$LABEL.plist"
DST="$HOME/Library/LaunchAgents/$LABEL.plist"
RUNTIME_DIR="${ASG_RUNTIME_DIR:-$HOME/.agent-security-gateway}"
PYTHON_BIN="${ASG_PYTHON:-python3}"

mkdir -p "$HOME/Library/LaunchAgents" "$RUNTIME_DIR/logs"
sed \
  -e "s#__ROOT__#$ROOT#g" \
  -e "s#__RUNTIME_DIR__#$RUNTIME_DIR#g" \
  -e "s#__PYTHON_BIN__#$PYTHON_BIN#g" \
  "$SRC" > "$DST"
chmod 600 "$DST"

launchctl bootout "gui/$(id -u)" "$DST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$DST"
launchctl enable "gui/$(id -u)/$LABEL"
launchctl kickstart -k "gui/$(id -u)/$LABEL"
echo "installed and started $LABEL"
