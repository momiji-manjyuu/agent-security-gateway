#!/usr/bin/env bash
# ASG golden image builder (root)。使い方: sudo ./build-golden.sh v1
# Ubuntu (snapshot 固定) + Xfce + TigerVNC、squashfs(zstd) 読み取り専用 rootfs + 起動時 tmpfs overlay。
# 秘密情報を含めない。完成済みバージョン (MANIFEST.sha256 あり) は絶対に上書きしない。
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
CONF=${ASG_GOLDEN_CONF:-$(dirname "$(readlink -f "$0")")/golden.env}; [[ -f $CONF ]] && . "$CONF"
VER=${1:?version e.g. v1}
ASG_ROOT=${ASG_ROOT:-/srv/asg}; G=$ASG_ROOT/golden; D=$G/$VER
GRP=${ASG_GROUP:-asg}; ORCH=${ASG_ORCH_USER:-asg-orch}
SUITE=${UBUNTU_SUITE:-noble}; SNAP=${UBUNTU_SNAPSHOT:-20261022T000000Z}
MIRROR=${UBUNTU_MIRROR:-https://snapshot.ubuntu.com/ubuntu/$SNAP}   # http は https へ 301 されるので最初から https
KV=${KERNEL_VERSION:-6.18.58}; KSRC=${KERNEL_OUT_DIR:-$ASG_ROOT/kernel/$KV}
GUSER=${GUEST_USER:-worker}; GUID=${GUEST_UID:-1000}
VD=${VNC_DISPLAY:-1}; VPORT=$((5900+VD)); GEOM=${VNC_GEOMETRY:-1600x900}
DNS=${GUEST_DNS:-1.1.1.1 9.9.9.9}; OVSZ=${GUEST_OVERLAY_TMPFS_SIZE:-2G}
APT=(-o Acquire::Retries=5 -o Acquire::http::Timeout=60 -o Acquire::https::Timeout=60)
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1792540800} LC_ALL=C DEBIAN_FRONTEND=noninteractive
LOGD=$ASG_ROOT/logs; install -d -m0750 -o "$ORCH" -g "$GRP" "$LOGD"
LOG=$LOGD/golden-$VER-$(date +%Y%m%dT%H%M%S).log
exec > >(tee -a "$LOG") 2>&1; echo "log: $LOG"
if [[ -e $D ]]; then
  [[ -f $D/MANIFEST.sha256 ]] && { echo "$D is COMPLETE — refusing to overwrite (make a new version)"; exit 1; }
  echo "removing INCOMPLETE $D"; chmod -R u+w "$D"; rm -rf "$D"; fi
for o in /var/tmp/asg-golden.*; do [[ -d $o ]] || continue      # 過去の失敗ビルドの残骸を掃除
  for m in dev proc sys; do umount -R "$o/rootfs/$m" 2>/dev/null || true; done
  findmnt -R "$o" >/dev/null 2>&1 && { echo "still mounted: $o"; exit 1; }; rm -rf "$o"; done
[[ -f $KSRC/vmlinux ]] || { echo "kernel not built: $KSRC/vmlinux"; exit 1; }
# 0. harness ゲート: harness を含める場合 gitleaks が通らなければ中止
if [[ -n ${HARNESS_DIR:-} ]]; then
  command -v gitleaks >/dev/null || { echo "gitleaks required"; exit 1; }
  if [[ -d $HARNESS_DIR/.git ]]; then gitleaks git --redact "$HARNESS_DIR" || { echo "gitleaks findings — abort"; exit 1; }; fi
  gitleaks dir --redact "$HARNESS_DIR" || { echo "gitleaks findings — abort"; exit 1; }
fi
W=$(mktemp -d /var/tmp/asg-golden.XXXX); R=$W/rootfs
trap 'umount -R "$R/proc" "$R/sys" "$R/dev" 2>/dev/null || true' EXIT
for i in 1 2 3; do   # ミラーの一時エラー対策でリトライ
  debootstrap --variant=minbase --components=main,universe --include=ca-certificates "$SUITE" "$R" "$MIRROR" && break
  [[ $i == 3 ]] && exit 1; echo "debootstrap retry $i"; rm -rf "$R"; sleep 10; done
rm -f "$R/etc/resolv.conf"; cp -L /run/systemd/resolve/resolv.conf "$R/etc/resolv.conf"  # stub(127.0.0.53) は chroot で不安定
cat > "$R/etc/apt/sources.list" <<S
deb $MIRROR $SUITE main universe
deb $MIRROR $SUITE-updates main universe
deb $MIRROR $SUITE-security main universe
S
mount --bind /dev "$R/dev"; mount -t proc proc "$R/proc"; mount -t sysfs sys "$R/sys"
chroot "$R" apt-get "${APT[@]}" update
chroot "$R" apt-get "${APT[@]}" install -y --no-install-recommends systemd-sysv udev dbus dbus-x11 iproute2 ca-certificates \
  python3 xfce4-session xfwm4 xfce4-panel xfdesktop4 xfce4-terminal thunar xfonts-base fonts-dejavu-core \
  tigervnc-standalone-server tigervnc-tools x11-xserver-utils ${EXTRA_PACKAGES:-}
chroot "$R" apt-get "${APT[@]}" -y dist-upgrade
chroot "$R" useradd -m -s /bin/bash -u "$GUID" "$GUSER"     # パスワードなし・sudo なし
if [[ -n ${HARNESS_DIR:-} ]]; then cp -a "$HARNESS_DIR" "$R/opt/harness"; chown -R root:root "$R/opt/harness"; fi
for n in $DNS; do echo "nameserver $n"; done > "$R/etc/resolv.conf.asg"
echo "${GUEST_HOSTNAME:-asg-worker}" > "$R/etc/hostname"
# VNC はパスワードなし (イメージに秘密を入れない)。到達性はホスト側 nft でホストのみに制限すること。
cat > "$R/etc/systemd/system/asg-xvnc.service" <<U
[Unit]
Description=ASG Xvnc :$VD (port $VPORT, host-only via host firewall)
After=network.target
[Service]
User=$GUSER
Environment=HOME=/home/$GUSER
ExecStartPre=+/bin/sh -c 'install -d -m1777 /tmp /tmp/.X11-unix /tmp/.ICE-unix; install -d -o $GUSER -g $GUSER -m0700 /home/$GUSER /home/$GUSER/.vnc /run/user/$GUID'
ExecStart=/usr/bin/Xtigervnc :$VD -rfbport $VPORT -interface 0.0.0.0 -SecurityTypes None -geometry $GEOM -depth 24 -AlwaysShared -nolisten tcp
Restart=on-failure
RestartSec=3
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
U
cat > "$R/etc/systemd/system/asg-xfce.service" <<U
[Unit]
Description=ASG Xfce session on :$VD
Requires=asg-xvnc.service
After=asg-xvnc.service
[Service]
User=$GUSER
Environment=HOME=/home/$GUSER DISPLAY=:$VD XDG_RUNTIME_DIR=/run/user/$GUID
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 50); do [ -S /tmp/.X11-unix/X$VD ] && exit 0; sleep 0.2; done; exit 1'
ExecStart=/usr/bin/dbus-launch --exit-with-session /usr/bin/startxfce4
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
U
chroot "$R" systemctl enable asg-xvnc.service asg-xfce.service
chroot "$R" systemctl mask systemd-random-seed.service apt-daily.timer apt-daily-upgrade.timer
# overlay init: 読み取り専用 squashfs を lower、tmpfs を upper にして pivot_root
cat > "$R/sbin/overlay-init" <<I
#!/bin/sh
mount -t proc proc /proc; mount -t tmpfs -o size=$OVSZ,mode=0755 tmpfs /mnt
mkdir -p /mnt/u /mnt/w /mnt/r
mount -t overlay overlay -o lowerdir=/,upperdir=/mnt/u,workdir=/mnt/w /mnt/r
chmod 1777 /mnt/r/tmp; chmod 0755 /mnt/r
mkdir -p /mnt/r/run/ro; cp /etc/resolv.conf.asg /mnt/r/etc/resolv.conf
cd /mnt/r; mkdir -p old; pivot_root . old
exec chroot . /sbin/init "\$@"
I
chmod 755 "$R/sbin/overlay-init"
# scrub: machine-id / seed / ssh host key / キャッシュ / ログ
: > "$R/etc/machine-id"; rm -f "$R/var/lib/dbus/machine-id" "$R/var/lib/systemd/random-seed" "$R"/etc/ssh/ssh_host_*
chroot "$R" apt-get clean; rm -f "$R/etc/resolv.conf"; ln -s /etc/resolv.conf.asg "$R/etc/resolv.conf"
rm -rf "$R"/var/lib/apt/lists/* "$R"/var/log/* "$R"/tmp/* "$R/root/.bash_history" "$R"/var/cache/*
chroot "$R" dpkg-query -W -f='${Package} ${Version}\n' > "$W/packages.txt"
umount -R "$R/proc" "$R/sys" "$R/dev"
# イメージツリーの簡易シークレットスキャン (必須で clean)
if grep -rIlE 'BEGIN [A-Z ]*PRIVATE KEY|api[_-]?key *=|AKIA[0-9A-Z]{16}' "$R" 2>/dev/null | grep -v -e ssl/certs -e "^$R/usr/"; then
  echo "secret-like content found — abort"; exit 1; fi
if command -v gitleaks >/dev/null; then gitleaks dir --redact "$R/etc" || { echo "gitleaks findings in /etc — abort"; exit 1; }; fi
# mtime を SOURCE_DATE_EPOCH に丸める。mksquashfs に -all-time/-mkfs-time は付けない (トラブルシュート参照)
find "$R" -newermt "@$SOURCE_DATE_EPOCH" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
install -d -m0750 -o root -g "$GRP" "$D"
mksquashfs "$R" "$D/rootfs.squashfs" -comp zstd -noappend -no-xattrs -quiet
install -m0440 -g "$GRP" "$KSRC/vmlinux" "$D/vmlinux"; install -m0444 "$KSRC/.config" "$D/kernel.config"
cp "$W/packages.txt" "$D/"
echo "mirror=$MIRROR snapshot=$SNAP suite=$SUITE kernel=$KV built=$(date -Is)" > "$D/BUILDINFO"
chmod 0440 "$D/rootfs.squashfs"; chgrp "$GRP" "$D"/*
( cd "$D" && sha256sum rootfs.squashfs vmlinux kernel.config packages.txt BUILDINFO > MANIFEST.sha256 )
# TODO: MANIFEST.sha256 の署名 (MANIFEST.sha256.sig) は別ホストの鍵で行う
chmod -R a-w "$D"; ln -sfn "$VER" "$G/current.new" && mv -T "$G/current.new" "$G/current"
rm -rf "$W"
if [[ -n ${ASG_LOG_COPY_DIR:-} ]]; then install -d "$ASG_LOG_COPY_DIR"; install -m644 ${ASG_LOG_OWNER:+-o "$ASG_LOG_OWNER"} "$LOG" "$ASG_LOG_COPY_DIR/"; fi
cat "$D/MANIFEST.sha256"; echo "GOLDEN $VER DONE"
