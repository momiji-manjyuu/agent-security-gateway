#!/bin/zsh
set -euo pipefail

LABEL="com.user.agent-security-gateway"
DST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl bootout "gui/$(id -u)" "$DST" 2>/dev/null || true
rm -f "$DST"
echo "uninstalled $LABEL"
