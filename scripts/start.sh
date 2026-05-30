#!/bin/zsh
set -euo pipefail

CONFIG_PATH="${ASG_CONFIG:-$HOME/.agent-security-gateway/config.json}"
PYTHON_BIN="${ASG_PYTHON:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

exec "$PYTHON_BIN" "$ROOT/gateway.py" --config "$CONFIG_PATH" serve
