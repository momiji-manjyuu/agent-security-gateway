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

## フェーズ2の操作（設定や秘密を扱う。既定は変更なし）

```sh
# 秘密の生成: 値はファイルにだけ入り、画面には出ない。出るのは config に入れる token_sha256 のみ。既存ファイルは上書きしない。
python scripts/asgctl.py secrets init --dir <保護されたフォルダ> --name docker90_search            # --kind key で共有鍵（HMAC等）
# 設定フラグメントのマージ: 既定は dry-run。衝突は拒否（上書きしない）。--write でバックアップ→検証→置換。
python scripts/asgctl.py fragment merge --into <config.json> --from <fragment.json> --map controller=<実際の親ID> --token-sha256 <新規エージェント>=<hex>
python scripts/asgctl.py fragment merge ... --write                                                  # 書き込み後に ASG の再起動が必要
# run の登録（親のトークンファイルを読むが、表示しない。接続先はループバックのみ）
python scripts/asgctl.py runs register --token-file <親のトークン> --body run-registration.json
```

- `fragment merge` は、既存のエージェントでは**トークン・階層・CIDR を保持**し、能力とルートの追加だけを行う。
  新規エージェントにはトークンのハッシュが必須（`REPLACE_WITH_*` が残っていれば拒否）。
- 既存のルートと**異なる定義**は衝突として拒否する。人が差分を確認して決める。
- 別ホストへ秘密を渡す作業（共有鍵のコピー、ハブの `authorized_keys` への追記）は**人が行う**。
- トンネルの専用鍵と常駐化は [presets/parent/tunnel/](../presets/parent/tunnel/README.md)（登録は `-Apply` を付けた時だけ）。

## まだ無いもの（今後のフェーズ）

`apply`（全自動の適用）、囮・キルスイッチの自動化、評価ゾーンの導入。親機の MCP は [presets/parent/mcp/](../presets/parent/mcp/README.md)。設計は
[docs/design/setup-and-connectivity.md](../docs/design/setup-and-connectivity.md)。
