#!/bin/sh
# Render the cloud-init seed (user-data, meta-data, network-config) into a directory, and optionally an ISO.
# Used by the libvirt / VirtualBox / QEMU scripts. POSIX sh, no dependencies beyond the ISO tool.
#
#   render-seed.sh --name NAME --pubkey FILE --out DIR [--profile offline|logged_egress]
#                  [--host-ip IP] [--guest-ip IP --prefix N | --dhcp]
#                  [--egress-ip IP --egress-port PORT] [--iso FILE]
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
name="" pubkey="" out="" profile="offline" host_ip="172.29.91.1" guest_ip="172.29.91.2" prefix="29"
dhcp=0 egress_ip="" egress_port="" iso=""

die() { echo "asg-lab: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --name) name=$2; shift 2 ;;
    --pubkey) pubkey=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --profile) profile=$2; shift 2 ;;
    --host-ip) host_ip=$2; shift 2 ;;
    --guest-ip) guest_ip=$2; shift 2 ;;
    --prefix) prefix=$2; shift 2 ;;
    --dhcp) dhcp=1; shift ;;
    --egress-ip) egress_ip=$2; shift 2 ;;
    --egress-port) egress_port=$2; shift 2 ;;
    --iso) iso=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$name" ] && [ -n "$pubkey" ] && [ -n "$out" ] || die "need --name, --pubkey, --out"
printf '%s' "$name" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$' || die "bad --name"
[ -r "$pubkey" ] || die "cannot read public key file"
grep -q 'PRIVATE KEY' "$pubkey" && die "that file looks like a PRIVATE key; pass the .pub file"
key=$(head -n 1 "$pubkey" | tr -d '\r')
printf '%s' "$key" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]+( .*)?$' || die "not a recognizable ssh public key"
case "$profile" in
  offline) rules="$here/nftables.offline.conf" ;;
  logged_egress)
    [ -n "$egress_ip" ] && [ -n "$egress_port" ] || die "logged_egress needs --egress-ip and --egress-port"
    rules="$here/nftables.logged_egress.conf" ;;
  *) die "bad --profile" ;;
esac

mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Escape for sed replacement (the key contains '/', '+', '=').
esc() { printf '%s' "$1" | sed -e 's/[\/&|]/\\&/g'; }

fill() {
  sed -e "s|__HOSTNAME__|$(esc "$name")|g" \
      -e "s|__LAB_SSH_PUBLIC_KEY__|$(esc "$key")|g" \
      -e "s|__PROFILE__|$(esc "$profile")|g" \
      -e "s|__HOST_IP__|$(esc "$host_ip")|g" \
      -e "s|__GUEST_IP__|$(esc "$guest_ip")|g" \
      -e "s|__PREFIX__|$(esc "$prefix")|g" \
      -e "s|__EGRESS_PROXY_IP__|$(esc "$egress_ip")|g" \
      -e "s|__EGRESS_PROXY_PORT__|$(esc "$egress_port")|g"
}

fill < "$rules" | sed 's/^/      /' > "$tmp/rules.indented"
# Insert the indented rules where the template says __NFTABLES_RULES__.
awk -v f="$tmp/rules.indented" '
  $0 == "__NFTABLES_RULES__" { while ((getline line < f) > 0) print line; next }
  { print }' "$here/user-data.template" | fill > "$out/user-data"

if [ "$dhcp" -eq 1 ]; then
  fill < "$here/network-config.dhcp.template" > "$out/network-config"
else
  sed -e '/^__ROUTES__$/d' "$here/network-config.static.template" | fill > "$out/network-config"
fi
printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$name" "$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')" "$name" > "$out/meta-data"

if grep -n '__[A-Z_][A-Z_]*__' "$out/user-data" "$out/meta-data" "$out/network-config" >&2; then
  die "unfilled placeholder in rendered seed"
fi
chmod 600 "$out/user-data" "$out/meta-data" "$out/network-config" 2>/dev/null || true

if [ -n "$iso" ]; then
  if command -v genisoimage >/dev/null 2>&1; then tool="genisoimage"
  elif command -v mkisofs >/dev/null 2>&1; then tool="mkisofs"
  elif command -v xorrisofs >/dev/null 2>&1; then tool="xorrisofs"
  elif command -v hdiutil >/dev/null 2>&1; then tool="hdiutil"
  else die "need genisoimage, mkisofs, xorrisofs or hdiutil to build the seed ISO"; fi
  if [ "$tool" = "hdiutil" ]; then
    rm -f "$iso" "$iso.cdr"
    hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$iso.cdr" "$out"
    mv "$iso.cdr" "$iso"
  else
    "$tool" -quiet -output "$iso" -volid cidata -joliet -rock "$out/user-data" "$out/meta-data" "$out/network-config"
  fi
fi
echo "rendered seed for $name (profile=$profile) in $out"
