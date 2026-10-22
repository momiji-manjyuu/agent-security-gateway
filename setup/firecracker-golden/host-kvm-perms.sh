#!/usr/bin/env bash
# /dev/kvm を kvm:0660・ユーザー ACL なしに恒久固定 (root, 冪等)。
# デスクトップ版 Ubuntu では 73-seat-late.rules の uaccess タグでログインユーザーに ACL が付くため、
# それより前 (72-) でタグを外す。加えて起動後 oneshot で再設定する。
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
echo 'SUBSYSTEM=="misc", KERNEL=="kvm", TAG-="uaccess", TAG-="seat", GROUP="kvm", MODE="0660"' > /etc/udev/rules.d/72-asg-kvm.rules
cat > /usr/local/sbin/asg-kvm-perms <<'P'
#!/bin/sh
chgrp kvm /dev/kvm && chmod 0660 /dev/kvm && setfacl -b /dev/kvm
P
chmod 0755 /usr/local/sbin/asg-kvm-perms
cat > /etc/systemd/system/asg-kvm-perms.service <<'U'
[Unit]
Description=ASG: /dev/kvm kvm:0660, no ACL
After=systemd-udev-settle.service systemd-logind.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/asg-kvm-perms
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload; systemctl enable asg-kvm-perms.service
udevadm control --reload-rules; udevadm trigger --name-match=kvm --action=change || true; sleep 1
/usr/local/sbin/asg-kvm-perms
ls -l /dev/kvm; getfacl -p /dev/kvm | grep -v '^#'
