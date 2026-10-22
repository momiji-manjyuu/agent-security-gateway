#!/usr/bin/env bash
# ワーカーホストの基本セットアップ (root, 冪等)。Ubuntu 24.04 想定。
# ユーザー/グループ, /srv/asg ツリー, ブリッジ, IPv6 無効化, DNS 固定, cups/avahi 停止,
# 任意で sshd ハードニング (SSHD_ALLOW_USERS を明示した場合のみ)。
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
HERE=$(dirname "$(readlink -f "$0")")
CONF=${ASG_GOLDEN_CONF:-$HERE/golden.env}; [[ -f $CONF ]] && . "$CONF"
ROOT=${ASG_ROOT:-/srv/asg}; GRP=${ASG_GROUP:-asg}; ORCH=${ASG_ORCH_USER:-asg-orch}
BR=${BRIDGE:-asgbr0}; BRIP=${BRIDGE_IP:-10.90.0.1}; PFX=${WORKER_CIDR:-10.90.0.0/24}; PFX=${PFX#*/}
RUN_SIZE=${ASG_RUN_TMPFS_SIZE:-16G}

echo "== 1. packages"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y nftables acl jq debootstrap squashfs-tools e2fsprogs \
  cpu-checker build-essential flex bison bc libelf-dev libssl-dev dwarves cpio ubuntu-keyring
kvm-ok || true

echo "== 2. users/groups (ログインユーザーは kvm に入れない)"
getent group "$GRP" >/dev/null || groupadd --system "$GRP"
id "$ORCH" &>/dev/null || useradd --system --gid "$GRP" --home "$ROOT/orchestrator" --shell /usr/sbin/nologin "$ORCH"
usermod -aG kvm "$ORCH"

echo "== 3. /srv/asg tree"
install -d -m0755 -o root -g root "$ROOT" "$ROOT/bin"
install -d -m0750 -o root -g "$GRP" "$ROOT/golden" "$ROOT/kernel" "$ROOT/knowledge"
install -d -m0700 -o "$ORCH" -g "$GRP" "$ROOT/orchestrator" "$ROOT/orchestrator/secrets"
install -d -m0770 -o "$ORCH" -g "$GRP" "$ROOT/quarantine" "$ROOT/quarantine/proposals"
install -d -m0750 -o "$ORCH" -g "$GRP" "$ROOT/quarantine/reviewed" "$ROOT/logs"
cat > /etc/systemd/system/run-asg.mount <<U
[Unit]
Description=ASG worker scratch (tmpfs, wiped on reboot)
[Mount]
What=tmpfs
Where=/run/asg
Type=tmpfs
Options=mode=0750,size=$RUN_SIZE,nosuid,nodev,uid=$ORCH,gid=$GRP
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload; systemctl enable --now run-asg.mount

echo "== 4. bridge $BR ($BRIP/$PFX, systemd-networkd)"
printf '[NetDev]\nName=%s\nKind=bridge\n' "$BR" > "/etc/systemd/network/50-$BR.netdev"
printf '[Match]\nName=%s\n[Network]\nAddress=%s/%s\nConfigureWithoutCarrier=yes\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n' \
  "$BR" "$BRIP" "$PFX" > "/etc/systemd/network/50-$BR.network"
systemctl enable systemd-networkd; systemctl restart systemd-networkd
command -v nmcli >/dev/null && nmcli dev set "$BR" managed no 2>/dev/null || true

if [[ ${DISABLE_IPV6:-1} == 1 ]]; then
  echo "== 5. IPv6 disable (host-wide)"
  printf 'net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\nnet.ipv6.conf.lo.disable_ipv6=1\n' \
    > /etc/sysctl.d/62-asg-disable-ipv6.conf
  sysctl -q -p /etc/sysctl.d/62-asg-disable-ipv6.conf
  [[ -f /etc/default/ufw ]] && sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
  [[ -n ${HOST_DNS:-} ]] || echo "WARN: リゾルバが IPv6 (RA) のみだと名前解決が壊れます。HOST_DNS を設定してください"
fi

if [[ -n ${HOST_DNS:-} ]]; then
  echo "== 6. DNS pin -> $HOST_DNS"
  if command -v nmcli >/dev/null && [[ -n ${WAN_IF:-} ]] && C=$(nmcli -g GENERAL.CONNECTION dev show "$WAN_IF" 2>/dev/null) && [[ -n $C ]]; then
    nmcli con mod "$C" ipv4.dns "$HOST_DNS" ipv4.ignore-auto-dns yes
    [[ ${DISABLE_IPV6:-1} == 1 ]] && nmcli con mod "$C" ipv6.method disabled
    nmcli con up "$C" >/dev/null
  else
    install -d /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNS=%s\n' "$HOST_DNS" > /etc/systemd/resolved.conf.d/50-asg.conf; systemctl restart systemd-resolved
  fi
  sleep 3; getent hosts archive.ubuntu.com >/dev/null && echo "DNS OK" || echo "WARN: DNS failing"
fi

if [[ ${DISABLE_CUPS_AVAHI:-1} == 1 ]]; then
  echo "== 7. disable cups/avahi"
  systemctl disable --now cups cups-browsed avahi-daemon.socket avahi-daemon 2>/dev/null || true
fi

echo "== 8. sysctl hardening"
printf 'kernel.kptr_restrict=2\nkernel.dmesg_restrict=1\nkernel.unprivileged_bpf_disabled=1\nnet.core.bpf_jit_harden=2\nkernel.yama.ptrace_scope=2\n' \
  > /etc/sysctl.d/60-asg.conf; sysctl -q --system || true

if [[ -n ${SSHD_ALLOW_USERS:-} ]]; then
  echo "== 9. sshd hardening (AllowUsers $SSHD_ALLOW_USERS)"
  F=/etc/ssh/sshd_config.d/10-asg-hardening.conf; BAK=$(mktemp)
  [[ -f $F ]] && cp "$F" "$BAK" || : > "$BAK"
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers %s\n' "$SSHD_ALLOW_USERS" > "$F"
  if sshd -t; then systemctl reload ssh || systemctl reload sshd
    echo "!! 現在のセッションを閉じる前に、新しい SSH 接続でログインできることを確認してください"
  else echo "sshd -t failed — reverting"; if [[ -s $BAK ]]; then cp "$BAK" "$F"; else rm -f "$F"; fi; exit 1; fi
else
  echo "== 9. sshd: SSHD_ALLOW_USERS 未設定のため変更しません"
fi
echo "== next: sudo $HERE/host-kvm-perms.sh && sudo $HERE/host-network.sh"
