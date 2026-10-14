# セットアップ手順書（AIエージェント向け）

目的: ASG の各ホストを、決まった順序で安全に整える。**まず `asgctl` で確認し、変更は人の承認を得てから行う。**
現状（フェーズ1）の `asgctl` は**読み取り専用**で、ホストを変更しない。

## 守ること

1. **秘密を読まない・出さない。** `.env`、トークン、秘密鍵、設定ファイル内の値は開かない。`asgctl` は環境変数を**名前だけ**報告する。
2. **ファイアウォール、セキュリティ設定、アカウント、鍵の登録は人が行う。** 手順とコマンドを示して止まる。
3. **既存のVM・スイッチ・コンテナ・サービスを変更しない。** 新規に作る物だけ作る。
4. 実行前に `plan`、実行後に `verify`。`fail` が残ったら次へ進まず、人に報告する。

## 流れ

```sh
python scripts/asgctl.py doctor --role <hub|parent|isolated-lab> --human   # 今の状態
python scripts/asgctl.py plan   --role <role> --human                      # 残りの手順（todo/done/manual）
python scripts/asgctl.py verify --role <role> --human                      # 動作確認
python scripts/asgctl.py verify --role isolated-lab --deep --human         # ゲストFWを一時的に外してホスト側の遮断を確認（終了時に自動復元）
```

- 出力は既定でJSON。`status` は `ok` / `warn` / `fail` / `skip`。終了コードは `fail` があれば 1。
- 各 `check` に `hint` があれば、それが次の一手。
- 役割の定義は `setup/roles/<role>.json`。ホストのアドレス等の例は `setup/inventory.example.json`（実物は `inventory.local.json`、git管理外）。

## ロール別の要点

| ロール | 確認すること | 人が行うこと |
|---|---|---|
| `hub` | ASG が `127.0.0.1` だけで待受（`asg_port_bind`）。`/healthz` と `/readyz` が ok | 設定の `bind` を変更して再起動、トンネル用鍵の発行 |
| `parent` | Python 3.10+、SSH、ループバックのトンネル | トンネルを張る、トークンの配置 |
| `isolated-lab` | Hyper-V、VMの隔離設定、`baseline-clean`、ホストFW規則、ゲストの外向き遮断 | `Block-LabToHost.ps1` の実行（管理者） |

VM の作成手順は [docs/runbooks/isolated-lab-setup.md](../docs/runbooks/isolated-lab-setup.md)、ひな形は
[presets/isolated/vm/](../presets/isolated/vm/README.md)。

## まだ無いもの（今後のフェーズ）

`apply`、`secrets init`、`fragment merge`、`runs register`、`asg-mcp`、囮・キルスイッチの自動化。設計は
[docs/design/setup-and-connectivity.md](../docs/design/setup-and-connectivity.md)。
