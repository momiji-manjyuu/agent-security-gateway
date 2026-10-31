#!/usr/bin/env bash
# Install the research service on the worker host (run as root, interactively; type the key yourself, never script it).
#   sudo bash install-research.sh <worker-host-LAN-IP> [key file, mode 0600, owned by root or the sudo user; shredded after use]
# Installs: /usr/local/lib/asg/research_service.py, /etc/asg/research-service.json (if absent), the systemd unit,
# /etc/asg/research.env (0600, service user) and /etc/asg/research-register.key (0600, root).
# It does NOT install SearXNG (operator choice, see README.md) and does not touch the hub.
# Secrets: you are asked for the hub's backend signing key (hidden input). The register key is generated here.
set -euo pipefail
IP=${1:?usage: install-research.sh <worker-host-LAN-IP>}
[[ $IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && $IP != 0.0.0.0 && $IP != 127.* ]] || { echo "bad LAN IP"; exit 2; }
D=$(cd "$(dirname "$0")" && pwd)
for f in research_service.py asg-research.service research-service.example.json; do sed -i 's/\r$//' "$D/$f"; done
python3 -m py_compile "$D/research_service.py"
getent group asg >/dev/null || groupadd --system asg
id asg-research >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --gid asg asg-research
install -d -m0755 /usr/local/lib/asg /etc/asg
TS=$(date +%Y%m%d%H%M%S)
for f in /usr/local/lib/asg/research_service.py /etc/systemd/system/asg-research.service; do [[ -f $f ]] && install -m0600 -o root -g root "$f" "$f.bak-$TS"; done
install -m0644 -o root -g root "$D/research_service.py" /usr/local/lib/asg/research_service.py
install -m0644 -o root -g root "$D/asg-research.service" /etc/systemd/system/asg-research.service
if [[ ! -f /etc/asg/research-service.json ]]; then
  sed "s/\"listen_host\": \"[^\"]*\"/\"listen_host\": \"$IP\"/" "$D/research-service.example.json" > /etc/asg/research-service.json
  chmod 0644 /etc/asg/research-service.json
fi
if [[ ! -f /etc/asg/research.env ]]; then
  if [[ -n ${2:-} ]]; then
    # key delivered as a file (for example piped from the hub by the operator, never shown); it is read once and shredded
    OWN=$(stat -c %u "$2" 2>/dev/null || echo x)
    [[ -f $2 && ! -L $2 && ( $OWN == 0 || $OWN == "${SUDO_UID:-0}" ) && $(( 8#$(stat -c %a "$2") & 8#077 )) -eq 0 ]] || { echo "key file must be a regular file owned by root or the sudo user, mode 0600"; exit 2; }
    HUBKEY=$(head -n1 "$2" | tr -d '\015'); shred -u "$2"
  else
    IFS= read -rs -p "Hub backend signing key (same value as the hub's ASG_BACKEND_HMAC_KEY, >= 32 chars, hidden): " HUBKEY; echo
  fi
  [[ ${#HUBKEY} -ge 32 && $HUBKEY =~ ^[^[:space:]]+$ ]] || { echo "key must be >= 32 chars without whitespace"; exit 2; }
  REG=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
  umask 077
  printf 'ASG_BACKEND_HMAC_KEY=%s\nASG_RESEARCH_REGISTER_KEY=%s\n' "$HUBKEY" "$REG" > /etc/asg/research.env
  printf '%s\n' "$REG" > /etc/asg/research-register.key
  chown asg-research:asg /etc/asg/research.env; chmod 0600 /etc/asg/research.env
  chown root:root /etc/asg/research-register.key; chmod 0600 /etc/asg/research-register.key
  unset HUBKEY REG
else
  echo "keep existing /etc/asg/research.env"
fi
# point the orchestrator at the service (known keys only; the file is parsed as data, root-owned, not writable by others)
touch /etc/asg/fc-worker.env; chown root:root /etc/asg/fc-worker.env; chmod 0644 /etc/asg/fc-worker.env
grep -q '^ASG_FC_RESEARCH_URL=' /etc/asg/fc-worker.env || echo "ASG_FC_RESEARCH_URL=http://$IP:8790" >> /etc/asg/fc-worker.env
grep -q '^ASG_FC_RESEARCH_KEY_FILE=' /etc/asg/fc-worker.env || echo "ASG_FC_RESEARCH_KEY_FILE=/etc/asg/research-register.key" >> /etc/asg/fc-worker.env
grep -q '^ASG_FC_TIMEOUT_MAX=' /etc/asg/fc-worker.env || echo "ASG_FC_TIMEOUT_MAX=3000" >> /etc/asg/fc-worker.env
systemctl daemon-reload
systemctl enable asg-research >/dev/null
systemctl restart asg-research
sleep 1
systemctl is-active asg-research
curl -fsS "http://$IP:8790/healthz" && echo
if ! curl -fsS -m 5 "http://127.0.0.1:8080/search?q=test&format=json" >/dev/null 2>&1; then
  echo "NOTE: SearXNG is not answering on 127.0.0.1:8080 (JSON format). Install it per README.md; /search will fail until then."
fi
sha256sum /usr/local/lib/asg/research_service.py
echo INSTALL_RESEARCH_DONE
