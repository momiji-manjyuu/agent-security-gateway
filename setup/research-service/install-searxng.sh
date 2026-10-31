#!/usr/bin/env bash
# Install SearXNG (local search backend for the research service) on the worker host. Run as root, interactively.
#   sudo bash install-searxng.sh <40-hex-commit>
# You choose and review the commit; moving branches are refused. Binds 127.0.0.1:8080 only, JSON enabled, limiter off
# (the research service is the only client). Python dependencies come from PyPI inside a private virtualenv.
# Re-running with another commit is an update (the settings file and secret key are kept).
set -euo pipefail
REF=${1:?usage: install-searxng.sh <40-hex-commit>}
[[ $REF =~ ^[0-9a-f]{40}$ ]] || { echo "pass the full 40-hex commit id you reviewed"; exit 2; }
D=$(cd "$(dirname "$0")" && pwd)
sed -i 's/\r$//' "$D/searxng.service"
apt-get install -y python3-dev python3-venv git build-essential libxslt-dev zlib1g-dev libffi-dev libssl-dev >/dev/null
id searxng >/dev/null 2>&1 || useradd --system --home-dir /usr/local/searxng --create-home --shell /usr/sbin/nologin searxng
SRC=/usr/local/searxng/searxng-src; VENV=/usr/local/searxng/searx-pyenv
[[ -d $SRC/.git ]] || sudo -u searxng git clone https://github.com/searxng/searxng "$SRC"
sudo -u searxng git -C "$SRC" fetch --quiet origin
sudo -u searxng git -C "$SRC" -c advice.detachedHead=false checkout --quiet "$REF"
[[ $(sudo -u searxng git -C "$SRC" rev-parse HEAD) == "$REF" ]] || { echo "checkout did not land on $REF"; exit 1; }
[[ -d $VENV ]] || sudo -u searxng python3 -m venv "$VENV"
sudo -u searxng "$VENV/bin/pip" install --quiet -U pip setuptools wheel pyyaml
# pinned runtime dependencies of this commit first (the package's own setup imports some of them, e.g. msgspec)
sudo -u searxng "$VENV/bin/pip" install --quiet -r "$SRC/requirements.txt"
sudo -u searxng "$VENV/bin/pip" install --quiet --use-pep517 --no-build-isolation -e "$SRC"
install -d -m0755 /etc/searxng
if [[ ! -f /etc/searxng/settings.yml ]]; then
  KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  umask 027
  cat > /etc/searxng/settings.yml <<EOF
# Overrides on top of SearXNG's defaults (use_default_settings). Local-only backend for the ASG research service.
use_default_settings: true
general:
  instance_name: "asg-research"
search:
  safe_search: 1
  formats: [html, json]
server:
  bind_address: "127.0.0.1"
  port: 8080
  secret_key: "$KEY"
  limiter: false
  image_proxy: false
EOF
  chown root:searxng /etc/searxng/settings.yml; chmod 0640 /etc/searxng/settings.yml
  unset KEY
fi
install -m0644 -o root -g root "$D/searxng.service" /etc/systemd/system/searxng.service
systemctl daemon-reload
systemctl enable searxng >/dev/null
systemctl restart searxng
for _ in $(seq 1 30); do curl -fsS -m 3 "http://127.0.0.1:8080/search?q=test&format=json" >/dev/null 2>&1 && break; sleep 2; done
OUT=$(curl -fsS -m 10 "http://127.0.0.1:8080/search?q=docker+none+network&format=json")  # no pipe into head: SIGPIPE + pipefail would abort here
echo "${OUT:0:300}"
ss -ltn | grep ':8080 ' || true
echo INSTALL_SEARXNG_DONE
