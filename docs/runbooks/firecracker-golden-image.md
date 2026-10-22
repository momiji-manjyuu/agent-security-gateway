# Firecracker microVM ワーカー用 golden image ビルド手順

隔離ワーカーホスト (Ubuntu 24.04 / KVM) 上で、ASG ワーカー用の Firecracker microVM イメージ
(ゲストカーネル + 読み取り専用 rootfs) を再現可能にビルドし、起動テストするための手順です。
スクリプトは `setup/firecracker-golden/` にあります。

> 実績: Firecracker v1.17.0 / ゲストカーネル 6.18.58 LTS / Ubuntu 24.04 rootfs で
> 起動テスト v2 が PASS し、VNC 経由で Xfce デスクトップを確認済み (2026-10-23)。

## 構成概要

| 項目 | 既定値 | 変数 |
|---|---|---|
| Firecracker | v1.17.0 (公式リリース, SHA256SUMS 検証) | `FC_BIN` |
| ゲストカーネル | 6.18.58 LTS, GPG 検証, Firecracker `microvm-kernel-ci-x86_64-6.18.config` | `KERNEL_VERSION`, `KERNEL_*` |
| rootfs | Ubuntu 24.04 (noble) debootstrap minbase, https スナップショットミラー | `UBUNTU_SUITE`, `UBUNTU_SNAPSHOT`, `UBUNTU_MIRROR` |
| デスクトップ | Xfce + Xtigervnc `:1` (port 5901), `asg-xvnc.service` / `asg-xfce.service` | `VNC_DISPLAY`, `VNC_GEOMETRY`, `GUEST_USER` |
| ディスク | squashfs (zstd) 読み取り専用 + `/sbin/overlay-init` による tmpfs overlay | `GUEST_OVERLAY_TMPFS_SIZE` |
| 配置 | `/srv/asg/golden/vN/` (+ `MANIFEST.sha256`), `current` シンボリックリンク | `ASG_ROOT` |
| サイズ | 2 vCPU / 6 GiB / ワーカー | `VCPU_COUNT`, `MEM_MIB` |
| ネットワーク | ブリッジ `asgbr0` 10.90.0.1/24, ゲスト 10.90.0.2 | `BRIDGE`, `BRIDGE_IP`, `GUEST_IP`, `NETMASK`, `TAP_DEV`, `GUEST_MAC` |
| 実行ユーザー | `asg-orch` (kvm グループ) を `setpriv` で | `ASG_ORCH_USER`, `ASG_GROUP` |

設定は `setup/firecracker-golden/golden.env.example` を `golden.env` にコピーして編集します
(または `ASG_GOLDEN_CONF=/path/to/file`)。各変数はシェル環境変数でも上書きできます。
**設定ファイルにパスワード・鍵・トークンを書かないこと。** イメージ自体も秘密を持たない設計です。

## 前提 (ホスト側, root)

1. パッケージ: `debootstrap squashfs-tools acl jq nftables` とカーネルビルド依存 (`build-essential flex bison bc libelf-dev libssl-dev`)。
2. ユーザー/グループ: `asg` グループ、`asg-orch` (system, nologin, `kvm` 所属)。ログインユーザーは kvm に入れない。
3. ディレクトリ: `/srv/asg/{bin,golden,kernel,logs}`、`/run/asg` は tmpfs (`mode=0750,uid=asg-orch,gid=asg`)。
4. Firecracker: 公式リリースを `sha256sum -c SHA256SUMS` で検証後 `/srv/asg/bin/` に配置し、`PINNED.sha256` を記録。
5. ブリッジ (systemd-networkd):
   ```ini
   # /etc/systemd/network/50-asgbr0.netdev
   [NetDev]
   Name=asgbr0
   Kind=bridge
   # /etc/systemd/network/50-asgbr0.network
   [Match]
   Name=asgbr0
   [Network]
   Address=10.90.0.1/24
   ConfigureWithoutCarrier=yes
   LinkLocalAddressing=no
   IPv6AcceptRA=no
   ```
   NAT/転送とファイアウォール (LAN へのルーティング禁止、VNC はホストからのみ) は nftables で別途設定。
6. `/dev/kvm` 権限: `sudo ./host-kvm-perms.sh` (下記トラブルシュート参照)。

## 手順

```bash
cd setup/firecracker-golden
cp golden.env.example golden.env   # 必要に応じて編集

# 1) カーネル (一般ユーザーで)。tarball/.sign/config を $KERNEL_SRC_DIR に置き、ハッシュを固定して実行
KERNEL_TARBALL_SHA256=<sha256> KERNEL_CONFIG_SHA256=<sha256> ./build-kernel.sh
sudo install -d -m0750 -g asg /srv/asg/kernel/6.18.58
sudo install -m0440 -g asg ~/asg-kernel/out/6.18.58/{vmlinux,.config} /srv/asg/kernel/6.18.58/

# 2) golden image (新しいバージョン名で。完成済みは上書き拒否)
sudo ./build-golden.sh v1

# 3) 起動テスト (ping + VNC ポート到達で PASS)
sudo ./boot-test.sh v1
sudo HOLD=1 ./boot-test.sh v1      # 600 秒保持して VNC 目視確認 (ssh -L 5901:10.90.0.2:5901 <host>)
```

成果物 (`/srv/asg/golden/vN/`): `rootfs.squashfs`, `vmlinux`, `kernel.config`, `packages.txt`, `BUILDINFO`, `MANIFEST.sha256`。
完成後は `chmod -R a-w` され、`current` が原子的に切り替わります。ロールバックは `current` を旧バージョンに戻すだけです。

## セキュリティ規約

- イメージに秘密情報 (パスワード, 秘密鍵, SSH ホスト鍵, API トークン) を含めない。VNC はパスワードなしで、到達性をホストのファイアウォールで制限する。
- ビルド時に machine-id / random-seed / ssh_host_* / apt リスト / ログを削除し、簡易シークレットスキャンを実行 (gitleaks があれば併用)。
- **harness をイメージに入れる場合 (`HARNESS_DIR`)、gitleaks が通らない限りビルドは中止される。**
- 完成済みバージョンは上書きしない。新しい `vN` を作る。
- MANIFEST の署名は今後の TODO (別ホストの鍵で `MANIFEST.sha256.sig` を作成)。

## トラブルシュート

| 症状 | 原因 | 対処 |
|---|---|---|
| debootstrap が途中で失敗 / `ca-certificates` 不足で https apt が失敗 | ミラーの一時エラー、http→https 301、CA 未導入 | https ミラーを直接指定、`--include=ca-certificates`、apt に `Acquire::Retries=5`、debootstrap を 3 回リトライ (スクリプト内蔵)。スナップショット障害時は `UBUNTU_SNAPSHOT` を別日付に、または `UBUNTU_MIRROR` (非再現。BUILDINFO に記録される) |
| chroot 内の名前解決失敗 | ホストの `/etc/resolv.conf` が stub (127.0.0.53) | `/run/systemd/resolve/resolv.conf` をコピー (内蔵) |
| mksquashfs が失敗/タイムスタンプが不正 | `SOURCE_DATE_EPOCH` 設定時に `-all-time` / `-mkfs-time` を併用すると衝突 | これらのオプションを付けない。mtime は事前に `find -newermt ... touch` で丸める |
| firecracker が `T` (stopped) 状態で止まる | `timeout ... sudo -u` を pty 下で使うと SIGTTOU で停止 | `setpriv --reuid asg-orch --regid asg --init-groups` で起動し、stdin を `</dev/null`、serial をファイルへ |
| `/dev/kvm` を asg-orch が開けない / ログインユーザーに ACL が付く | `73-seat-late.rules` の uaccess タグがユーザー ACL を付与 | `72-asg-kvm.rules` (73 より前) で `TAG-="uaccess", TAG-="seat", GROUP="kvm", MODE="0660"`、`asg-kvm-perms` oneshot サービス、boot-test 冒頭で再適用 (`host-kvm-perms.sh`) |
| ping は通るが VNC ポートが開かない | tigervncserver ラッパーの挙動 | `Xtigervnc` を直接起動し `-rfbport`/`-interface` を明示 (v2 の修正)。serial ログ (`journal+console`) を確認 |
| ブリッジが DOWN でゲストに届かない | TAP 未接続時に networkd が設定しない | `.network` に `ConfigureWithoutCarrier=yes`、boot-test で `ip link set asgbr0 up` |
| `removing INCOMPLETE` / `still mounted` | 前回ビルドの残骸 | スクリプトが自動で umount・削除。`still mounted` の場合は手動で `findmnt -R /var/tmp/asg-golden.*` を確認 |
| Windows から転送したスクリプトが動かない | CRLF 改行 | `sed -i 's/\r$//' *.sh` 後 `bash -n` で確認 |
