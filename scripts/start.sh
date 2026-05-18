#!/bin/zsh
set -euo pipefail

CONFIG_PATH="${ASP_CONFIG:-$HOME/.agent-security-proxy/config.json}"
PYTHON_BIN="${ASP_PYTHON:-/usr/local/bin/python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

exec "$PYTHON_BIN" "$ROOT/proxy.py" --config "$CONFIG_PATH" serve
