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

ホスト準備は 3 本のスクリプトで行います (いずれも冪等。実行前に内容と `golden.env` を必ずレビュー)。

```bash
sudo ./host-setup.sh       # パッケージ, asg グループ/asg-orch (kvm), /srv/asg ツリー, /run/asg tmpfs, ブリッジ, IPv6 無効化, DNS 固定, cups/avahi 停止, sysctl, (任意) sshd
sudo ./host-kvm-perms.sh   # /dev/kvm を kvm:0660・ACL なしに固定
sudo ./host-network.sh     # nftables `inet asg` + asg-nft.service
```

Firecracker は公式リリースを `sha256sum -c SHA256SUMS` で検証後 `/srv/asg/bin/` に配置し、`PINNED.sha256` を記録してください。

### host-setup.sh の注意

- `HOST_DNS` を設定すること。リゾルバがルーター広告 (IPv6) 由来のみの環境では、IPv6 無効化で名前解決が壊れます。
- sshd は **`SSHD_ALLOW_USERS` を明示した場合のみ** 変更します (既定値なし = 変更しない)。`sshd -t` に失敗したら元に戻します。適用後、既存セッションを閉じる前に新しい接続でログインできることを確認してください。
- ログインユーザーは kvm グループに入れません。VM は `asg-orch` だけが起動します。

### ネットワーク隔離 (host-network.sh)

Ubuntu 標準の `nftables.service` とは独立した `asg-nft.service` が `/etc/nftables.d/asg.nft` (生成物) を読み込みます。
ufw と共存します (優先度 -10 の別テーブル。ここでの drop は最終)。設定値:
`WAN_IF`, `BRIDGE`, `WORKER_CIDR`, `LAN_CIDR`, `LAN_BCAST`, `LAN_GW`, `ASG_IP`, `ASG_PORT` (既定 8788)。
例の値は文書用アドレス (192.0.2.0/24) なので **必ず自環境の値に置き換えてください**。

| 通信 | 扱い |
|---|---|
| ワーカー → インターネット (IPv4) | NAT (masquerade) で許可 |
| ワーカー → `ASG_IP:ASG_PORT` (tcp) | 許可 (LAN 唯一の例外) |
| ワーカー → LAN / RFC1918 / 100.64/10 / 169.254/16 / ループバック / マルチキャスト等 | 遮断 |
| ワーカー IPv6 | 全遮断 |
| ワーカー → ホスト自身 (新規) | 遮断 (ゲスト DNS は公開リゾルバを使う) |
| ホスト → LAN (新規) | `ASG_IP` と `LAN_GW` の DNS(53)/DHCP(67) のみ |
| ホスト IPv6 | `lo` 以外遮断 (sysctl でも無効化) |

ufw が有効な場合 (routed=deny) は `ufw route allow in on $BRIDGE out on $WAN_IF` を追加します (フィルタは `inet asg` 側)。

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

### MANIFEST の署名と検証

秘密鍵は **ワーカーホストに置かず**、管理用の親ホスト (署名ホスト) に保管します。鍵はスクリプトでは生成しません。
署名ホストで一度だけ手動作成してください (例: `ssh-keygen -t ed25519 -f ~/.ssh/asg-golden-sign` / `minisign -G`)。

1. ワーカーホスト: `sha256sum /srv/asg/golden/vN/MANIFEST.sha256` を控え、MANIFEST を署名ホストへコピー。
2. 署名ホスト: `SIGN_KEY=<秘密鍵パス> ./sign-manifest.sh MANIFEST.sha256` (ハッシュ一致を確認) → `MANIFEST.sha256.sig`。
3. ワーカーホスト: 公開鍵を `VERIFY_PUBKEY` に配置。
   - `SIGN_METHOD=ssh`: allowed_signers 形式 `asg-golden ssh-ed25519 AAAA...` (principal = `SIGN_IDENTITY`)
   - `SIGN_METHOD=minisign`: minisign 公開鍵ファイル
4. ワーカーホスト: `sudo ./verify-manifest.sh --install MANIFEST.sha256.sig /srv/asg/golden/vN` (検証に通った場合のみ配置)。

`boot-test.sh` などの利用側は `verify-manifest.sh` を呼び、ハッシュ (`--strict`) と署名を検証します。
不正な署名は常に拒否、`ASG_REQUIRE_SIGNED=1` では未署名・公開鍵なしも拒否します (運用では 1 を推奨)。

成果物 (`/srv/asg/golden/vN/`): `rootfs.squashfs`, `vmlinux`, `kernel.config`, `packages.txt`, `BUILDINFO`, `MANIFEST.sha256`。
完成後は `chmod -R a-w` され、`current` が原子的に切り替わります。ロールバックは `current` を旧バージョンに戻すだけです。

## セキュリティ規約

- イメージに秘密情報 (パスワード, 秘密鍵, SSH ホスト鍵, API トークン) を含めない。VNC はパスワードなしで、到達性をホストのファイアウォールで制限する。
- ビルド時に machine-id / random-seed / ssh_host_* / apt リスト / ログを削除し、簡易シークレットスキャンを実行 (gitleaks があれば併用)。
- **harness をイメージに入れる場合 (`HARNESS_DIR`)、gitleaks が通らない限りビルドは中止される。**
- 完成済みバージョンは上書きしない。新しい `vN` を作る。
- MANIFEST は別ホストの鍵で署名し、`ASG_REQUIRE_SIGNED=1` で未署名イメージを起動させない。秘密鍵・公開鍵とも repo にコミットしない。

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
| IPv6 無効化後に名前解決できない | リゾルバがルーター広告 (IPv6) 由来のみ | `HOST_DNS` で IPv4 リゾルバを固定 (host-setup.sh) |
| ワーカーから外に出られない | ufw routed=deny / ip_forward=0 / `WAN_IF` 誤り | `ufw route allow`、`sysctl net.ipv4.ip_forward`、`nft list table inet asg` のカウンタを確認 |
| `SIGNATURE_INVALID` / `UNSIGNED ... refused` | 署名不一致、公開鍵未配置、principal/namespace 不一致 | `VERIFY_PUBKEY`, `SIGN_IDENTITY`, `SIGN_NAMESPACE` を確認し、正しい MANIFEST に再署名 |
