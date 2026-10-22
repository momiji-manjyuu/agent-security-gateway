#!/usr/bin/env bash
# golden image の MANIFEST.sha256 の署名とハッシュを検証する (公開鍵のみ使用)。
# 使い方: verify-manifest.sh <golden-dir>                 検証のみ
#         sudo verify-manifest.sh --install <sig> <golden-dir>  署名を検証して vN に配置 (root)
# ASG_REQUIRE_SIGNED=1 のとき、署名が無い/不正なら非 0 で終了する。
set -euo pipefail
CONF=${ASG_GOLDEN_CONF:-$(dirname "$(readlink -f "$0")")/golden.env}; [[ -f $CONF ]] && . "$CONF"
INSTALL=; if [[ ${1:-} == --install ]]; then INSTALL=${2:?sig file}; shift 2; fi
D=$(readlink -f "${1:?golden dir}"); M=$D/MANIFEST.sha256
PUB=${VERIFY_PUBKEY:-/etc/asg/golden-signers}
verify_sig() { # $1 = sig file
  case ${SIGN_METHOD:-ssh} in
    ssh) ssh-keygen -Y verify -f "$PUB" -I "${SIGN_IDENTITY:-asg-golden}" -n "${SIGN_NAMESPACE:-asg-golden}" -s "$1" < "$M" ;;
    minisign) minisign -V -q -p "$PUB" -m "$M" -x "$1" ;;
    *) echo "unknown SIGN_METHOD"; return 1 ;;
  esac; }
[[ -f $M ]] || { echo "no manifest: $M"; exit 1; }
if [[ -n $INSTALL ]]; then
  [[ $EUID -eq 0 ]] || { echo "--install needs root"; exit 1; }
  [[ -f $PUB ]] || { echo "public key/allowed_signers missing: $PUB"; exit 1; }
  verify_sig "$INSTALL" || { echo "SIGNATURE INVALID — not installed"; exit 1; }
  chmod u+w "$D"; install -m0444 "$INSTALL" "$M.sig"; chgrp "${ASG_GROUP:-asg}" "$M.sig" || true; chmod a-w "$D"
  echo "installed $M.sig"
fi
( cd "$D" && sha256sum -c --quiet --strict MANIFEST.sha256 ) || { echo "MANIFEST hash mismatch"; exit 1; }
if [[ -f $M.sig && -f $PUB ]]; then
  if verify_sig "$M.sig"; then echo "SIGNATURE_OK"; exit 0; fi
  echo "SIGNATURE_INVALID"; exit 1   # 不正署名は ASG_REQUIRE_SIGNED に関わらず拒否
fi
if [[ ${ASG_REQUIRE_SIGNED:-0} == 1 ]]; then echo "UNSIGNED (or no public key at $PUB) — refused (ASG_REQUIRE_SIGNED=1)"; exit 1; fi
echo "WARN: unsigned manifest accepted (ASG_REQUIRE_SIGNED=0)"
