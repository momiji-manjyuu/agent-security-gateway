# ASG トンネル（親機 → ハブ、ループバックのみ）

ASG は `127.0.0.1` だけで待ち受けるので、他のホストは SSH トンネル経由で届く。ここは、そのトンネルを**専用鍵**で**常駐**させる部品。

| ファイル | 内容 | ホストを変更するか |
|---|---|---|
| `New-AsgTunnelKey.ps1` | 専用の鍵を作り、ハブ用の制限付き `authorized_keys` の1行を表示 | 親機に鍵ファイルを作るだけ |
| `Install-AsgTunnelTask.ps1` | 起動時に張る・切れたら再接続するスケジュールタスク | **既定は計画の表示のみ。`-Apply` で登録** |
| `asg-tunnel.service` | Linux 用の systemd ユーザーユニット | 手動で配置 |

## 手順

1. 親機で鍵を作る（秘密鍵は表示されない）。
   ```powershell
   .\New-AsgTunnelKey.ps1 -WhatIf
   .\New-AsgTunnelKey.ps1
   ```
2. **人が**、表示された1行をハブの `authorized_keys` に追加する。この鍵は `restrict`（シェル・pty・転送の既定を無効）に加え、
   `port-forwarding` と `permitopen="127.0.0.1:8788"` だけが許可される。Windows ハブで管理者アカウントの場合は
   `C:\ProgramData\ssh\administrators_authorized_keys`（ACL は Administrators と SYSTEM のみ）。
3. 初回だけ手動で接続し、**ハブのホスト鍵の指紋を確認して**信頼する（以後は `StrictHostKeyChecking=yes`）。
4. 計画を確認してから登録する。
   ```powershell
   .\Install-AsgTunnelTask.ps1 -HubHost <hub> -HubUser <user>            # 計画だけ
   .\Install-AsgTunnelTask.ps1 -HubHost <hub> -HubUser <user> -Apply     # 登録
   ```
5. `python scripts/asgctl.py verify --role parent --human` で `asg_via_tunnel` が ok であること。

## 逆向き（ハブ → ラボのランナー）

`New-AsgTunnelKey.ps1 -PermitListen 127.0.0.1:18790` で、ハブ側で `-R` の待受だけを許す鍵になる。

## 注意

- 鍵とタスクは**ホストの恒久的な設定**。登録は人が承認してから。AIエージェントは `-Apply` を勝手に付けない。
- 古い（共用の）鍵でトンネルを張っている場合は、専用鍵に切り替えたあと、古い鍵の権限を見直す。
