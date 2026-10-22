#!/usr/bin/env bash
# MANIFEST.sha256 に署名する。**署名ホスト (ワーカーホスト以外, 例: 管理用の親ホスト) で実行する。**
# 秘密鍵はワーカーホストに置かない。鍵の生成はこのスクリプトでは行わない (runbook 参照)。
# 使い方: ./sign-manifest.sh <path/to/MANIFEST.sha256>   → 同じ場所に MANIFEST.sha256.sig を出力
set -euo pipefail
CONF=${ASG_GOLDEN_CONF:-$(dirname "$(readlink -f "$0")")/golden.env}; [[ -f $CONF ]] && . "$CONF"
M=${1:?MANIFEST.sha256 path}; KEY=${SIGN_KEY:?set SIGN_KEY (private key path on the signing host)}
[[ -f $M ]] || { echo "no such file: $M"; exit 1; }
sha256sum "$M"; echo "上記ハッシュがワーカーホスト上の MANIFEST と一致することを確認してから署名してください"
case ${SIGN_METHOD:-ssh} in
  ssh) rm -f "$M.sig"; ssh-keygen -Y sign -f "$KEY" -n "${SIGN_NAMESPACE:-asg-golden}" "$M" ;;
  minisign) minisign -S -s "$KEY" -m "$M" -x "$M.sig" ;;
  *) echo "unknown SIGN_METHOD"; exit 1 ;;
esac
echo "signed: $M.sig  (ワーカーホストへ転送し verify-manifest.sh --install で配置)"
