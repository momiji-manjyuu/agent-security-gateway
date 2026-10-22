#!/usr/bin/env bash
# 単発 microVM 起動テスト (root): sudo ./boot-test.sh v1   (HOLD=1 で VNC 確認用に 600 秒保持)
# firecracker は TTY なし (stdin </dev/null, serial → ファイル) で setpriv により非特権ユーザーとして起動する。
# `timeout ... sudo -u` で pty 下から起動すると SIGTTOU で停止 (T 状態) するため使わない。
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
CONF=${ASG_GOLDEN_CONF:-$(dirname "$(readlink -f "$0")")/golden.env}; [[ -f $CONF ]] && . "$CONF"
[[ -x /usr/local/sbin/asg-kvm-perms ]] && /usr/local/sbin/asg-kvm-perms   # /dev/kvm 権限を再確認
VER=${1:-current}; ASG_ROOT=${ASG_ROOT:-/srv/asg}; G=$ASG_ROOT/golden/$VER
GRP=${ASG_GROUP:-asg}; ORCH=${ASG_ORCH_USER:-asg-orch}; FCB=${FC_BIN:-$ASG_ROOT/bin/firecracker}
BR=${BRIDGE:-asgbr0}; BRIP=${BRIDGE_IP:-10.90.0.1}; GIP=${GUEST_IP:-10.90.0.2}; NM=${NETMASK:-255.255.255.0}
TAP=${TAP_DEV:-asgtap-t}; MAC=${GUEST_MAC:-06:00:0a:5a:00:02}
VCPU=${VCPU_COUNT:-2}; MEM=${MEM_MIB:-6144}; VPORT=$((5900+${VNC_DISPLAY:-1})); TMO=${BOOT_TIMEOUT_S:-180}
ID=test-$(date +%s); RUN=/run/asg/$ID; LOGD=${ASG_LOG_COPY_DIR:-$ASG_ROOT/logs}; install -d "$LOGD"
SER=$LOGD/serial-$ID.log; FCLOG=$RUN/fc.log
"$(dirname "$(readlink -f "$0")")/verify-manifest.sh" "$G"   # ハッシュ + 署名 (ASG_REQUIRE_SIGNED=1 で未署名拒否)
setpriv --reuid "$ORCH" --regid "$GRP" --init-groups test -r /dev/kvm -a -w /dev/kvm || { echo "$ORCH cannot open /dev/kvm"; exit 1; }
install -d -o "$ORCH" -g "$GRP" "$RUN"
ip link set "$BR" up
ip link del "$TAP" 2>/dev/null || true
ip tuntap add dev "$TAP" mode tap user "$ORCH"
ip link set "$TAP" master "$BR" up; bridge link set dev "$TAP" isolated on
cat > "$RUN/vm.json" <<J
{ "boot-source": { "kernel_image_path": "$G/vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 rootfstype=squashfs init=/sbin/overlay-init ip=$GIP::$BRIP:$NM::eth0:off" },
  "drives": [ { "drive_id": "rootfs", "path_on_host": "$G/rootfs.squashfs", "is_root_device": true, "is_read_only": true } ],
  "machine-config": { "vcpu_count": $VCPU, "mem_size_mib": $MEM },
  "network-interfaces": [ { "iface_id": "eth0", "host_dev_name": "$TAP", "guest_mac": "$MAC" } ],
  "entropy": {},
  "logger": { "log_path": "$FCLOG", "level": "Info", "show_level": true } }
J
: > "$FCLOG"; chown "$ORCH:$GRP" "$RUN/vm.json" "$FCLOG"
echo "Booting $ID; serial -> $SER"
setpriv --reuid "$ORCH" --regid "$GRP" --init-groups -- \
  "$FCB" --no-api --config-file "$RUN/vm.json" </dev/null >"$SER" 2>&1 &
FC=$!; OK=0
for i in $(seq 1 $((TMO/5))); do sleep 5
  kill -0 $FC 2>/dev/null || { echo "firecracker exited"; break; }
  if ping -c1 -W1 "$GIP" >/dev/null 2>&1; then echo "PING_OK (t=$((i*5))s)"
    if timeout 3 bash -c "</dev/tcp/$GIP/$VPORT" 2>/dev/null; then echo "VNC_PORT_OPEN"; OK=1; break; fi; fi
done
echo "--- process state: $(ps -o stat= -p $FC 2>/dev/null || echo gone)"
if [[ ${HOLD:-0} == 1 && $OK == 1 ]]; then echo "HOLD=1: 600s (例: ssh -L $VPORT:$GIP:$VPORT <host>)"; sleep 600; fi
kill $FC 2>/dev/null || true; sleep 2; kill -9 $FC 2>/dev/null || true; wait $FC 2>/dev/null || true
cp "$FCLOG" "$LOGD/fc-$ID.log" 2>/dev/null || true
echo "--- serial tail:"; tail -n 25 "$SER" | tr -d '\r'
ip link del "$TAP" || true; rm -rf "$RUN"
[[ $OK == 1 ]] && echo "BOOT_TEST_PASS" || { echo "BOOT_TEST_FAIL (see $SER, $LOGD/fc-$ID.log)"; exit 1; }
