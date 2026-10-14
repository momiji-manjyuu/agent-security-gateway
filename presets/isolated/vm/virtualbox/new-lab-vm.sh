#!/bin/sh
# Create an isolated Linux lab VM with VirtualBox (Linux / macOS Intel hosts; Windows: run under Git Bash or WSL).
#   new-lab-vm.sh --name NAME --base-image noble-server-cloudimg-amd64.img --pubkey lab.pub [--profile offline] [--dry-run]
# Needs: VBoxManage, qemu-img, and one of genisoimage/mkisofs/xorrisofs/hdiutil.
# Network: a host-only adapter (management SSH only). No NAT, no bridged adapter.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
common="$here/../common"
name="" base="" pubkey="" profile="offline" mem=8192 cpus=4 disk=61440 root="${ASG_LAB_ROOT:-$HOME/asg-lab}" dry=0
hostonly="${ASG_LAB_HOSTONLY_IF:-vboxnet0}" egress_ip="" egress_port=""

die() { echo "asg-lab: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --name) name=$2; shift 2 ;; --base-image) base=$2; shift 2 ;; --pubkey) pubkey=$2; shift 2 ;;
    --profile) profile=$2; shift 2 ;; --memory-mb) mem=$2; shift 2 ;; --cpus) cpus=$2; shift 2 ;;
    --disk-mb) disk=$2; shift 2 ;; --root) root=$2; shift 2 ;; --dry-run) dry=1; shift ;;
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
# vboxnet0 defaults to 192.168.56.1/24; the guest address must live in the same subnet.
# shellcheck disable=SC2086
sh "$common/render-seed.sh" --name "$name" --pubkey "$pubkey" --out "$vmdir/seed" --profile "$profile" \
   --host-ip 192.168.56.1 --guest-ip 192.168.56.2 --prefix 24 $extra --iso "$vmdir/seed.iso"
run qemu-img convert -f qcow2 -O raw "$base" "$vmdir/disk.raw"
run VBoxManage convertfromraw "$vmdir/disk.raw" "$vmdir/disk.vdi" --format VDI
run VBoxManage modifymedium disk "$vmdir/disk.vdi" --resize "$disk"
run rm -f "$vmdir/disk.raw"

run VBoxManage createvm --name "$name" --ostype Ubuntu_64 --basefolder "$root" --register
run VBoxManage modifyvm "$name" --memory "$mem" --cpus "$cpus" --firmware efi \
  --nic1 hostonly --hostonlyadapter1 "$hostonly" --nictype1 virtio \
  --clipboard-mode disabled --draganddrop disabled --audio-enabled off --usb off --usbehci off --usbxhci off \
  --vrde off --graphicscontroller vmsvga --accelerate3d off --nested-hw-virt off --mouse ps2 --keyboard ps2
run VBoxManage storagectl "$name" --name SATA --add sata --controller IntelAhci
run VBoxManage storageattach "$name" --storagectl SATA --port 0 --device 0 --type hdd --medium "$vmdir/disk.vdi"
run VBoxManage storageattach "$name" --storagectl SATA --port 1 --device 0 --type dvddrive --medium "$vmdir/seed.iso"

echo "created $name (host-only $hostonly). Never add shared folders. Start headless: VBoxManage startvm $name --type headless"
echo "snapshot after provisioning: VBoxManage snapshot $name take baseline-clean"
echo "freeze: VBoxManage controlvm $name setlinkstate1 off && VBoxManage controlvm $name savestate"
