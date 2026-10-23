#!/usr/bin/env bash
# Install the disposable-worker orchestrator on the Firecracker host (run once as root, after host-setup.sh and a golden image).
#   sudo bash install-worker.sh <orchestrating-login-user>
# Installs: /usr/local/sbin/asg-fc-worker, /usr/local/lib/asg/worker_agent.py, one NOPASSWD sudoers rule for that user,
# and /etc/asg/fc-worker.env from the example if absent. No secrets are installed on this host.
set -euo pipefail
U=${1:?usage: install-worker.sh <login-user>}
[[ $U =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "bad user"; exit 2; }
D=$(cd "$(dirname "$0")" && pwd)
for f in asg-fc-worker worker_agent.py; do sed -i 's/\r$//' "$D/$f"; done
bash -n "$D/asg-fc-worker"; python3 -m py_compile "$D/worker_agent.py"
install -d -m0755 /usr/local/lib/asg /etc/asg
# re-running is an update: keep the previous versions (root-only) for rollback
TS=$(date +%Y%m%d%H%M%S)
for f in /usr/local/sbin/asg-fc-worker /usr/local/lib/asg/worker_agent.py; do [[ -f $f ]] && install -m0600 -o root -g root "$f" "$f.bak-$TS"; done
install -m0644 -o root -g root "$D/worker_agent.py" /usr/local/lib/asg/worker_agent.py
install -m0755 -o root -g root "$D/asg-fc-worker" /usr/local/sbin/asg-fc-worker
[[ -f /etc/asg/fc-worker.env ]] || install -m0644 -o root -g root "$D/fc-worker.env.example" /etc/asg/fc-worker.env
T=$(mktemp); echo "$U ALL=(root) NOPASSWD: /usr/local/sbin/asg-fc-worker" > "$T"
visudo -cf "$T"; install -m0440 -o root -g root "$T" /etc/sudoers.d/asg-fc-worker; rm -f "$T"; visudo -c >/dev/null
sha256sum /usr/local/sbin/asg-fc-worker /usr/local/lib/asg/worker_agent.py
echo INSTALL_WORKER_DONE
