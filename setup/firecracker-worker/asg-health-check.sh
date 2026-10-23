#!/bin/sh
# ASG health monitor on the worker host (user crontab, no root). Logs up/down state changes only.
#   */2 * * * * ASG_HEALTH_URL=http://10.90.0.1:8788/healthz $HOME/asg-setup/asg-health-check.sh
# ASG_HEALTH_URL defaults to the bridge address/port used by setup/firecracker-golden (BRIDGE_IP, ASG_PORT).
URL=${ASG_HEALTH_URL:-http://10.90.0.1:8788/healthz}
STATE="$HOME/.asg-health.state"; LOG="$HOME/asg-health.log"
if curl -fsS -m 10 -o /dev/null "$URL"; then NOW=up; else NOW=down; fi
PREV=$(cat "$STATE" 2>/dev/null || echo unknown)
if [ "$NOW" != "$PREV" ]; then echo "$(date -Is) asg $PREV -> $NOW" >> "$LOG"; echo "$NOW" > "$STATE"; fi
