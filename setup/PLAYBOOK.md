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
python scripts/asgctl.py secrets init --dir <保護されたフォルダ> --name lab_worker            # --kind key で共有鍵（HMAC等）
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

## 実環境への導入手順（一般化した知見）

以下は特定環境の値ではなく、**設定する手順**である。実ホスト名・実IP・実モデル名・
実トークン／ハッシュはこの手順書にも設定例にも書かず、各ホスト上でだけ扱う。
例示は `<MODEL_HOST>`、`<MODEL_PORT>`、`<INSPECTOR_MODEL>`、`<WORKER_MODEL>` のような
プレースホルダと、汎用名（`parent` / `hub` / `isolated` / `lab_worker`）だけを使う。

### 1. モデル接続先とモデル名（信頼ホスト側の環境変数で選ぶ）

- モデル接続先は固定コードや呼び出し側の引数ではなく、**信頼ホスト側**の環境変数
  `MODEL_BROKER_HOST=<MODEL_HOST>` / `MODEL_BROKER_PORT=<MODEL_PORT>` で運用者が選ぶ。
  子（worker コンテナ）や呼び出し側に接続先・モデル名を選ばせない。
- 未設定・空・不正（ポートが数値でない、範囲外）なら推論は**失敗側に倒れる**（fail closed）。
  「とりあえず既定の宛先へつなぐ」フォールバックは入れない。
- モデル名も導入環境に合わせて運用者が選ぶ前提とする:
  inspector 用は `MODEL_BROKER_INSPECTOR_MODEL=<INSPECTOR_MODEL>`、
  worker 用は `MODEL_BROKER_WORKER_MODEL=<WORKER_MODEL>`。
  どちらかが未設定なら推論を開始しない。
- hub 側で inspector が使うモデル名（例: `llm_inspector.model`）と、リレー側で許可する
  inspector モデル名（上記 `MODEL_BROKER_INSPECTOR_MODEL`）は**一致**させる。
  一致しないと検査が error になり、`fail_closed=true` の場合は委任が入力ガードで止まる。
  切り分けは「hub 側設定のモデル名」と「リレーの `/healthz` が返すモデル名」の突き合わせから行う
  （値は手順書やチケットに転記せず、その場で照合して結果だけを記録する）。

### 2. 親ホストの MCP 設定（`asg-mcp`）を汎用名へ切り替える

対象は親ホストの `asg-mcp` 設定で、経路・worker を汎用名へ揃える:
`task_route=lab.web_research.task`、`submit_route=lab.artifacts.submit`、
`worker_agent=lab_worker`（雛形は `presets/parent/mcp/asg-mcp.example.json`）。

1. **切り替え前にバックアップ**: 変更する設定ファイルを、同じホスト上で日時付きの別名に複製する。
   バックアップ自体にも秘密の値は入れない（トークンはファイルパス参照のまま）。
2. 設定値（経路名・worker agent 名・有効化フラグ）だけを汎用名へ書き換える。接続先は
   ループバック／トンネルのままにし、モデルやツール引数で経路を選べるようにしない。
3. **確認手順**（この順で、失敗したら切り替えを進めない）:
   - JSON として妥当か: `python -m json.tool <asg-mcp設定> >/dev/null`
   - MCP 初期化とツール一覧が返るか（`initialize` → `tools/list`。ハーネスの MCP 登録画面、
     または stdio への JSON-RPC で確認する）
   - `asg_inspect` が既知の無害な文で応答するか（allow/block の列挙値だけを見る。本文は持ち込まない）
   - 委任が有効な構成では、状態確認（artifact status）が列挙値だけを返すか

### 3. 隔離ホストの runner を更新する

1. **対象ファイルのバックアップ**: runner 一式（`runner.py`、`model_broker.py`、
   `gateway_link.py` 等、配置するファイル）を置き換える前に、隔離ホスト上でバックアップを取る。
2. 配置後に、起動環境の `ASG_ALLOWED_CALLERS` に**実際の委任元 agent**（例: `<DELEGATING_AGENT>`）を
   含める。委任元と runner の許可リストがずれると、正しく署名された依頼でも署名検証
   （委任元チェック）で拒否される。切り分けでは、署名エラーと時刻ずれ（許容差内の同期）と
   許可リストの不一致を分けて確認する。
3. **再起動後の確認手順**:
   - runner が loopback だけで待受しているか（`asgctl verify --role isolated-runner` の
     `runner_port_bind` 相当）
   - 未署名リクエストが拒否されるか: 署名なし `POST /v1/tasks` が `401`/`403` で、
     処理が実行されないこと（`runner_refuses_unsigned` 相当）
   - トンネル経由で hub の `healthz` に届くか（隔離側のトンネル先 loopback で確認）
   - 署名済みの正規依頼が 1 回だけ実行され、同じ run/task の再送は冪等に扱われ、
     本文を変えた再送は競合として拒否されるか

### 4. 成果物提出用 worker agent の専用トークン

- 成果物提出用の worker agent（例: `lab_worker`）には、**他の agent と同一ではない専用トークン**を
  持たせる。同一トークンのハッシュを複数 agent が共有すると、hub 側で意図しない agent として
  解決され、route の許可や run の範囲チェックで拒否されることがある。
- 生成・配布の一般手順: 秘密値は**各ホスト上で生成**し、平文はそのホストの保護された
  ファイル／環境にだけ置く。hub へ登録するのは `token_sha256`（ハッシュ）だけにする。
  実値・実ハッシュを手順書、チケット、コミット、チャットに書かない
  （既存の `asgctl secrets init` と PLAYBOOK フェーズ2の手順を使う）。
- 切り分け手順: (a) hub 側で「解決された agent id」「許可 route」「run の caller 範囲」を
  順に確認する、(b) agent ごとにトークンのハッシュが一意か（重複登録がないか）を、
  値を見ずに件数と重複の有無だけで確認する、(c) それでもずれる場合は、その agent の
  トークンを各ホスト上で再生成してハッシュだけを再登録し、旧値を失効させる。

### 5. inspector モデル名の一致（hub ⇄ リレー）

§1 の繰り返しになる要点だけを独立した確認項目として残す: 導入・モデル変更のたびに、
hub 側 `llm_inspector` のモデル名とリレー側で許可するモデル名が一致しているかを照合する。
不一致のときの症状は「検査 error → `fail_closed` なら入力ガードで委任停止」であり、
モデルサーバー自体の障害、接続先（`MODEL_BROKER_HOST`/`MODEL_BROKER_PORT`）の未設定と
分けて切り分ける。

### 6. 切り戻し手順（全ホスト共通の一般手順）

1. 変更前に、各ホストで**設定ファイルと配置ファイルのバックアップ**を取る（§2・§3）。
   バックアップの場所と世代はホスト上で記録し、秘密の実値は記録に含めない。
2. 戻すときは、バックアップから復元してサービス（hub / MCP / runner / リレー）を再起動する。
   設定の手編集で継ぎ足して戻さない。
3. 復元後に `healthz`（hub は `/healthz` と `/readyz`、runner／リレーは各 `healthz`）で
   確認し、`asgctl verify --role <role>` が `fail` を残していないことを見てから通常運用に戻す。
4. 切り戻し後も、未署名拒否（§3）と inspect（§2）の最低限の拒否系確認を行う。

### 7. 備え付けテストの追随

隔離ホスト側の備え付けテスト（`examples/disposable-search-agent/tests/`）が、旧モデル名や
旧経路名・旧委任元名を期待して失敗する場合は、汎用名・現在前提（環境変数で選ぶモデル名、
許可リストに含まれる委任元）へテストを追随させる。**境界の拒否（未署名・許可外 caller・
モデル未設定での fail closed 等）の意図は弱めない**こと。追随後は、リポジトリのテストと
合わせて実行し、新規の失敗がないことを確認する。

## まだ無いもの（今後のフェーズ）

`apply`（全自動の適用）、囮・キルスイッチの自動化、評価ゾーンの導入。親機の MCP は [presets/parent/mcp/](../presets/parent/mcp/README.md)。設計は
[docs/design/setup-and-connectivity.md](../docs/design/setup-and-connectivity.md)。
