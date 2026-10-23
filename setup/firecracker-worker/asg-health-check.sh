#!/bin/sh
# Rev19: ASG health monitor on the worker host (user crontab, no root). Logs state changes only.
# */2 * * * * /home/user/asg-setup/asg-health-check.sh
STATE="$HOME/.asg-health.state"; LOG="$HOME/asg-health.log"
if curl -fsS -m 10 -o /dev/null http://10.90.0.1:8788/healthz; then NOW=up; else NOW=down; fi
PREV=$(cat "$STATE" 2>/dev/null || echo unknown)
if [ "$NOW" != "$PREV" ]; then echo "$(date -Is) asg $PREV -> $NOW" >> "$LOG"; echo "$NOW" > "$STATE"; fi
