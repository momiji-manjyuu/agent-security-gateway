#!/bin/sh
# Create an isolated Linux lab VM on libvirt/KVM (Linux host).
#   new-lab-vm.sh --name NAME --base-image noble-server-cloudimg-amd64.img --pubkey lab.pub [--profile offline] [--dry-run]
# Needs: virsh, virt-install, qemu-img, and one of genisoimage/mkisofs/xorrisofs.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
common="$here/../common"
name="" base="" pubkey="" profile="offline" mem=8192 cpus=4 disk=60 root="${ASG_LAB_ROOT:-$HOME/asg-lab}" dry=0
egress_ip="" egress_port=""

die() { echo "asg-lab: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --name) name=$2; shift 2 ;; --base-image) base=$2; shift 2 ;; --pubkey) pubkey=$2; shift 2 ;;
    --profile) profile=$2; shift 2 ;; --memory-mb) mem=$2; shift 2 ;; --cpus) cpus=$2; shift 2 ;;
    --disk-gb) disk=$2; shift 2 ;; --root) root=$2; shift 2 ;; --dry-run) dry=1; shift ;;
    --egress-ip) egress_ip=$2; shift 2 ;; --egress-port) egress_port=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ -n "$name" ] && [ -n "$base" ] && [ -n "$pubkey" ] || die "need --name, --base-image, --pubkey"
[ -r "$base" ] || die "cannot read base image"

run() { if [ "$dry" -eq 1 ]; then echo "+ $*"; else "$@"; fi; }
vmdir="$root/$name"
extra=""
[ "$profile" = "logged_egress" ] && extra="--egress-ip $egress_ip --egress-port $egress_port"

run mkdir -p "$vmdir"
# shellcheck disable=SC2086
sh "$common/render-seed.sh" --name "$name" --pubkey "$pubkey" --out "$vmdir/seed" --profile "$profile" \
   --host-ip 172.29.91.1 --guest-ip 172.29.91.2 --prefix 29 $extra --iso "$vmdir/seed.iso"
run qemu-img convert -f qcow2 -O qcow2 "$base" "$vmdir/disk.qcow2"
run qemu-img resize "$vmdir/disk.qcow2" "${disk}G"

if ! virsh net-info asg-lab >/dev/null 2>&1; then
  run virsh net-define "$here/asg-lab-net.xml"
  run virsh net-autostart asg-lab
fi
run virsh net-start asg-lab 2>/dev/null || true

# No --filesystem, no spice/clipboard channel, no USB redirection, no balloon, no sound, no graphics.
run virt-install --name "$name" --memory "$mem" --vcpus "$cpus" --import \
  --os-variant ubuntu24.04 \
  --disk "path=$vmdir/disk.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$vmdir/seed.iso,device=cdrom,readonly=on" \
  --network "network=asg-lab,model=virtio" \
  --graphics none --console pty,target_type=serial \
  --memballoon none --controller usb,model=none --sound none \
  --noautoconsole --noreboot

echo "created $name. Load host-firewall.nft (reviewed) before starting; then: virsh start $name"
echo "snapshot after provisioning:  virsh snapshot-create-as $name baseline-clean"
