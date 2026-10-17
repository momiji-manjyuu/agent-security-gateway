# ASGホストの設定担当者向け

## 追加するもの

- 隔離ホストのホストランナー宛て：`lab.web_research.task`（`http_json`）。
- 結果の隔離保管：`lab.artifacts.submit`（`inspect_only`）。
- 送信専用agent：`lab_worker`、能力は`submit_artifact`のみ。
- 親agentに`delegate_web_research`と依頼経路を追加。

`config.fragment.json`はマージする差分です。既存config全体の置換には使わないでください。親の仮ID`controller`を実際のIDに置換し、既存callerの能力・経路は保持してください。

境界修正版ASGでは、保管ルートの`artifact_policy.allowed_operations: ["submit"]`が必要です。この差分には追加済みです。隔離ホストへ以前コピーした設定にも同じ項目を反映してください。

## 接続

ASGの待受を`127.0.0.1:8788`と仮定。隔離ホストから張るSSHの`-L`と`-R`により、ASGから見たランナーは`http://127.0.0.1:18790/v1/tasks`、ランナーから見たASGは`http://127.0.0.1:18788`になります。実ポートが異なる場合はトンネルを合わせます。

トンネルでは`lab_worker`のASG接続元は`127.0.0.1`です。IPだけに依存せず、専用トークン・ルート・能力・runを必須にします。親が別の接続元を使う場合、親agentのCIDRは既存の実構成を維持します。

## 共有する秘密（チャットに貼らない）

| ASGホスト | 隔離ホスト |
|---|---|
| `ASG_SEARCH_BACKEND_KEY` | 同じ値を`SEARCH_BACKEND_TOKEN` |
| 既存`backend_hmac_key_env`の鍵 | 同じ値を`ASG_BACKEND_HMAC_KEY` |
| `lab_worker.token_sha256` | ハッシュ化前の値を`ASG_WORKER_TOKEN` |

既存のグローバル署名鍵を勝手に交換しないでください。ASG側の環境変数名が異なる場合、既存`backend_hmac_key_env`を維持し、その値を隔離ホストへ設定します。3組の値は対応する組だけ共有し、子コンテナには一切渡しません。

## runの範囲

`run-registration.example.json`には親の依頼経路とランナーの保管経路、両callerが入っています。親の既存`security.runs.register`経路から登録し、取得したIDを`task.example.json`へ入れます。ランナーにはrun登録・承認・親への命令・知識昇格・artifact downloadの能力を付与しません。

run登録経路がまだなければ、ASGリポジトリの登録経路例を既存の親設定へ追加してください。このひな形の差分には管理用の経路は含めていません。

## 出力の扱い

この接続は同期処理です。依頼のHTTP応答で資料IDと状態だけが返り、本文は`/v1/artifacts`の隔離ストアへ入ります。`/v1/results`で別途通知する必要はありません。

将来非同期の通知を追加する場合は、ASGの`report_policy.forward_audit_receipt=true`、`return_audit_receipt=true`、`include_structured_extract=false`を使う専用経路を検討してください。現時点でその経路を開通させる必要はありません。

`artifact_status=verified`でも親が本文を自動読込しない運用にします。自由文の要約を必要とする場合は別の隔離レビュー経路で扱います。

## 起動確認

実際の秘密を環境変数へ設定後、ASGの既存手順で`validate-config`を実行します。署名必須の経路は鍵が未設定なら失敗します。隔離ホストのDockerとPythonが準備できたら、まず`task.example.json`のURL指定テストを実施してください。

参照実装の基点：[agent-security-gateway / e9a251d](https://github.com/momiji-manjyuu/agent-security-gateway/tree/e9a251de9b8ac26112376e78f542d8110f14b7db)。同梱の境界修正を適用したASGで使用します。このひな形は実設定を自動変更しません。
