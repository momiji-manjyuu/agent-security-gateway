# 隔離ラボ VM のセットアップ手順（Hyper-V ＋ Linux ゲスト）

実際に構築して確認した手順と、つまずいた点の記録です。他の基盤は
[presets/isolated/vm/README.md](../../presets/isolated/vm/README.md) を参照。AIエージェントが実行する場合も、そのまま使えます。
アドレスとパスは例です（[setup/inventory.example.json](../../setup/inventory.example.json) を参照）。

## 前提

- 管理者権限で動く Windows 11 Pro/Enterprise。Hyper-V が有効（`Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All`）。
- 変換用に Docker Desktop（Linux エンジン）。**Docker が使えなければ、`qemu-img` を持つ別の環境で VHDX に変換しておく**。
- 空き容量 80GB 以上、メモリ 16GB 以上（VM に 8GB）。
- 作業を始める前に、既存の VM とスイッチを確認し、**触らない**（`Get-VM`、`Get-VMSwitch`）。

## 手順

1. **スクリプトをホストへ配置する。** `presets/isolated/vm/` を `Documents\ASG-Lab\vm-presets\` へコピー。
2. **管理用 SSH 鍵を作る。** パスフレーズなし、秘密鍵は所有者のみの権限にする。リポジトリに入れない。
   ```powershell
   ssh-keygen -t ed25519 -N '""' -C asg-lab -f $env:USERPROFILE\Documents\ASG-Lab\keys\lab_ed25519 -q
   icacls <鍵ファイル> /inheritance:r /grant:r "$($env:USERNAME):F"
   ```
   PowerShell 5.1 では空のパスフレーズを `'""'` と書く（`""` だと引数が消えて失敗する）。
3. **cloud image を取得して VHDX に変換する。**
   ```powershell
   .\hyperv\Convert-CloudImage.ps1                       # 既定: alpine:3 を使用
   .\hyperv\Convert-CloudImage.ps1 -ConverterImage python:3.12-slim-bookworm   # ローカルにある Debian 系を使う場合
   ```
   公式サイトの SHA-256 一覧と照合する。**照合は破損・不完全なダウンロードの検出であり、サイトの乗っ取りまでは防げない**。
   厳密にしたい場合は、別経路で得た値を `-ExpectedSha256` に渡す。
4. **VM を作る。** まず `-WhatIf` で内容を確認する（モジュール読み込みの別名メッセージが混ざるが無害）。
   ```powershell
   .\hyperv\New-AsgLabVm.ps1 -Name asg-lab-eval-01 -BaseVhdx <変換したvhdx> -SshPublicKeyFile <鍵.pub> -WhatIf
   .\hyperv\New-AsgLabVm.ps1 -Name asg-lab-eval-01 -BaseVhdx <変換したvhdx> -SshPublicKeyFile <鍵.pub> -Start
   ```
5. **ホストのファイアウォールを人が設定する。** `Block-LabToHost.ps1` を内容確認のうえ、管理者権限で実行する。
   これが無いと、ゲストから Hyper-V ホスト自身のサービス（SSH、Docker、SMB など）に届く。**AIエージェントは実行しない。**
6. **接続と確認。** 起動後 1〜2 分で `ssh lab@<ゲストIP>` が通る。
   ```powershell
   .\hyperv\Invoke-AsgLabSsh.ps1 -Command 'sudo asg-lab-selfcheck; cloud-init status'
   ```
   期待値: `profile=offline`、`firewall_table_present=true`、`ssh_password_auth=no`、`default_routes=0`、cloud-init が `done`。
7. **隔離を確認する。** ゲストから外部、LAN の他ホスト、ホスト自身へ接続できず、DNS も引けないこと。
8. **基準点を作る。** `Save-AsgLabCheckpoint.ps1 -Name asg-lab-eval-01 -Label baseline-clean`。評価ごとに `Restore-AsgLabCheckpoint.ps1` で戻す。

## 異常時（キルスイッチ）

```powershell
.\hyperv\Invoke-AsgLabFreeze.ps1 -Name asg-lab-eval-01 -Reason "<理由>"       # NICを切り、メモリごと保存して証拠を残す
.\hyperv\Invoke-AsgLabFreeze.ps1 -Name asg-lab-eval-01 -Destroy               # 電源断（メモリ内容は失われる）
.\hyperv\Restore-AsgLabCheckpoint.ps1 -Name asg-lab-eval-01                   # 解除は人間が行う
```

## つまずいた点

| 症状 | 原因 | 対処 |
|---|---|---|
| `ssh` が応答せず固まる | Windows の OpenSSH は、非対話の親（別の ssh セッション、サービス）から起動すると、継承した標準入出力で待ち続ける | `Invoke-AsgLabSsh.ps1` を使う（入出力をリダイレクトし、タイムアウトで終了） |
| `docker run` が `error getting credentials` | SSH 経由だと Docker Desktop の資格情報ヘルパーが使えない。新しいイメージの取得ができない | 取得済みの Debian 系イメージを `-ConverterImage` で指定する |
| `SHA256SUMS` に項目が無い | 取得結果がバイト列の場合があり、行の分割が崩れる | 修正済み（バイト列と改行コードを正規化） |
| 統合サービスの名前が一致しない | 日本語環境では名前が翻訳される | GUID で判定する（時刻同期のみ有効） |
| `New-VM` の引数エラー | `-NoVHD` と `-VHDPath` は併用できない | 修正済み |

## 運用上の注意

- ゲストの `lab` ユーザーは、使い捨てのため passwordless sudo を持つ。**ゲスト内の root は侵害されうる前提**で、ゲストに秘密を置かない。
- 管理用の鍵はホストに残る。ホストが侵害されればゲストも侵害される。ホストと共用の他サービスを持たせない（評価専用ホストが望ましい）。
- `logged_egress` は、ホスト側の記録つきプロキシを作るまで使わない。
