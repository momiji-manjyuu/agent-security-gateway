# 隔離ラボ VM ひな形

隔離ゾーン用の VM を、主要な仮想化基盤で同じ方針で作るためのひな形です。設計は
[docs/design/setup-and-connectivity.md](../../../docs/design/setup-and-connectivity.md) の §3 と §10 を参照。
状態: **初版（Linux ゲストは動作確認の対象、Windows ゲストは骨子のみ）**。

## 共通の約束

- 既定プロファイルは `offline`。ゲストは外へ出られず、入れるのはホストからの SSH だけ。
- 共有フォルダ、クリップボード、ドラッグ＆ドロップ、USB、リモート表示、音声、ゲストエージェントによるファイル転送は**使わない**。
- SSH は公開鍵のみ。パスワードは作らない。**秘密鍵・トークン・APIキーをシード（cloud-init）に入れない。**
- 評価後は `baseline-clean` チェックポイントへ復元する。異常時は**ホスト側から**ネットワークを切って凍結する（`freeze`）。
- `logged_egress` は、ホスト側の記録つきプロキシ（未実装、設計は §10）を立てた後にだけ使う。

## どれを使うか

| ホスト | 基盤 | スクリプト | ゲストのネットワーク |
|---|---|---|---|
| Windows | **Hyper-V** | `hyperv/New-AsgLabVm.ps1` | 内部スイッチ（NATなし）。`Block-LabToHost.ps1` でホスト側サービスへの到達を遮断（人が実行） |
| Linux | **libvirt / KVM** | `libvirt/new-lab-vm.sh` | 分離ネットワーク（forward なし）。`host-firewall.nft` で遮断 |
| Linux / macOS / Windows | **VirtualBox** | `virtualbox/new-lab-vm.sh` | ホストオンリー（NAT／ブリッジなし） |
| macOS（Apple Silicon / Intel）／Linux | **QEMU（UTMの中身）** | `qemu/new-lab-vm.sh` | `restrict=on`。ゲストはホストにも届かず、127.0.0.1 の転送で SSH のみ |
| 任意 | VMware Fusion/Workstation、UTM（GUI） | スクリプトなし | `common/render-seed.sh` でシード ISO を作り、ネットワークを「ホストオンリー」または「ネットワークなし」にして接続。共有・コピーは無効にする |

Windows ゲストは [windows-guest/](windows-guest/README.md)。実際に構築した手順とつまずいた点は [docs/runbooks/isolated-lab-setup.md](../../../docs/runbooks/isolated-lab-setup.md)、アドレスなどの設定例は [setup/inventory.example.json](../../../setup/inventory.example.json)。

## 使い方（共通の流れ）

1. 公式の cloud image を取得し、**SHA-256 を公式の一覧と照合**する（Hyper-V は `hyperv/Convert-CloudImage.ps1` が実施）。
   Apple Silicon では `arm64`、Intel／Windows／多くの Linux では `amd64` のイメージを選ぶ。
2. 管理用の SSH 鍵を作る（**秘密鍵はホストの保護された場所に置き、リポジトリに入れない**）。
   ```sh
   ssh-keygen -t ed25519 -N "" -C asg-lab -f ~/asg-lab/lab_ed25519
   ```
   パスフレーズなしにする場合は、鍵ファイルの権限を所有者のみにし、このホストを信頼境界として扱う。
3. 基盤のスクリプトを実行する（`--dry-run` / `-WhatIf` で内容を先に確認できる）。
4. 起動し、`ssh lab@<ゲスト>` で入って `sudo asg-lab-selfcheck` を実行。ファイアウォール表と SSH 設定が期待どおりか確認する。
5. `baseline-clean` を作る。以後は評価ごとに復元する。

## 作った後の確認項目

- ゲストから外部（例: 1.1.1.1、LAN の別ホスト、ホスト自身）へ接続できないこと。
- ホストから `ssh lab@…` が通り、パスワードでは入れないこと。
- 統合サービス（Hyper-V）／共有フォルダ（他基盤）が無いこと。
- 復元（`baseline-clean`）で、前回の評価の痕跡が消えること。

## 構成

```
common/        cloud-init テンプレート、nftables、プロファイル定義、シード生成 (render-seed.sh)
hyperv/        New-AsgLabVm / Convert-CloudImage / Save・Restore-Checkpoint / Invoke-AsgLabFreeze / Invoke-AsgLabSsh / Block-LabToHost
libvirt/       分離ネットワーク定義、ホストFW、new-lab-vm.sh
virtualbox/    new-lab-vm.sh
qemu/          new-lab-vm.sh（macOS/Linux）
windows-guest/ Windows ゲストの骨子
```
