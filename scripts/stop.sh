#!/bin/zsh
set -euo pipefail

LABEL="com.user.agent-security-proxy"
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/$LABEL.plist" 2>/dev/null || true
echo "stopped $LABEL"
