#!/usr/bin/env bash
# Firecracker ゲストカーネルを一般ユーザーでビルド (root 不要)。
# 事前に $KERNEL_SRC_DIR に linux-$KERNEL_VERSION.tar.xz, .tar.sign, Firecracker の
# microvm-kernel-ci-x86_64-<major.minor>.config を置き、kernel.org 署名鍵を $GNUPGHOME に import しておく。
set -euo pipefail
CONF=${ASG_GOLDEN_CONF:-$(dirname "$0")/golden.env}; [[ -f $CONF ]] && . "$CONF"
V=${KERNEL_VERSION:-6.18.58}
K=${KERNEL_WORK_DIR:-$HOME/asg-kernel}; SRC=${KERNEL_SRC_DIR:-$K/src}; OUT=${KERNEL_OUT_DIR:-$K/out/$V}
CFG=${KERNEL_CONFIG:-microvm-kernel-ci-x86_64-${V%.*}.config}
: "${KERNEL_TARBALL_SHA256:?pin sha256 of linux-$V.tar.xz}" "${KERNEL_CONFIG_SHA256:?pin sha256 of $CFG}"
# Greg Kroah-Hartman (stable) の鍵指紋。必ず kernel.org で確認してから使うこと。
SIGNER_FPR=${KERNEL_SIGNER_FPR:-647F28654894E3BD457199BE38DBBDC86092693E}
export GNUPGHOME=${GNUPGHOME:-$K/gnupg}
cd "$SRC"
echo "$KERNEL_TARBALL_SHA256  linux-$V.tar.xz" | sha256sum -c -
echo "$KERNEL_CONFIG_SHA256  $CFG" | sha256sum -c -
xz -cd "linux-$V.tar.xz" | gpg --batch --status-fd 1 --verify "linux-$V.tar.sign" - 2>/dev/null \
  | grep -q "VALIDSIG $SIGNER_FPR" || { echo "GPG verify FAILED"; exit 1; }
[[ -f $OUT/vmlinux ]] && { echo "already built: $OUT/vmlinux"; sha256sum "$OUT/vmlinux"; exit 0; }
rm -rf "$K/build/linux-$V"; mkdir -p "$K/build" "$OUT"; tar xJf "linux-$V.tar.xz" -C "$K/build"
cd "$K/build/linux-$V"; cp "$SRC/$CFG" .config
export KBUILD_BUILD_USER=asg KBUILD_BUILD_HOST=asg-build SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1792540800}
export KBUILD_BUILD_TIMESTAMP="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S UTC')"
make olddefconfig; make -j"$(nproc)" vmlinux
cp vmlinux .config "$OUT/"; cd "$OUT"; sha256sum vmlinux .config | tee SHA256SUMS; echo KERNEL_BUILD_DONE
