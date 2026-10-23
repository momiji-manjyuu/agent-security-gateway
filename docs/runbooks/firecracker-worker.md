# Firecracker 使い捨てワーカー (ASG 経由) 運用手順

`firecracker-golden-image.md` で作った golden image を使い、親エージェントから 1 タスクごとに使い捨て microVM を起動する。
ワーカーは **プロバイダの API キーを持たない**。モデル呼び出し・成果物提出はすべて ASG 経由で、親との直接リンクはない。

## 構成

```
親 (spawn_worker.py) ──ssh──> ワーカーホスト: sudo -n asg-fc-worker <run_id> <task_id>   (stdin: 資格情報 1 行 + spec JSON 1 行)
        │                                  └─ Firecracker microVM (golden 読み取り専用, tmpfs overlay)
        │                                        ├─ /dev/vdb: worker_agent.py (実行時注入, 読み取り専用)
        │                                        ├─ MMDS V2: タスク spec + run スコープの資格情報
        │                                        └─ 10.90.0.1:8788 → (逆 SSH トンネル) → ASG (127.0.0.1 bind)
        └──> ASG: /v1/runs 登録 → 成果物 metadata/content 取得 → run 失効
```

| ASG ルート | 呼び出し元 | 用途 |
|---|---|---|
| `security.runs.register` | 親 | run 登録 (TTL 600 s) と失効 (deny-all, TTL 1 s で再登録) |
| `fc.llm.chat` | fc_worker | 親と同じモデル (`model_rewrite`)。資格情報は ASG 側の `api_key_env` |
| `fc.artifacts.submit` | fc_worker | 回答を隔離領域へ提出 (内容スキャン) |
| `security.artifacts.download` | 親 | `verified` の成果物のみ取得 |
| `security.decoy.export` (canary) | — | 囮ルート。呼んだエージェントを失効 |

設定例: `examples/config.fc-worker.fragment.json`。

## 導入

1. ワーカーホスト: `sudo bash setup/firecracker-worker/install-worker.sh <親が ssh するユーザー>`。
   必要なら `/etc/asg/fc-worker.env` (root 所有) を編集。
2. ASG: fragment をマージする。`fc_worker` は `run_scoped: true` のテンプレートで静的トークンを持たない (`token_sha256: ""`)。
   `python gateway.py validate-config` → 再起動。
3. 親: `setup/firecracker-worker/spawn_worker.py` と `spawn_worker.example.json` を `~/.asg/` に置き、トークンファイルの ACL を本人のみに。
   MCP (stdio) として登録: `python spawn_worker.py mcp`、ツール名 `spawn_worker(task, urls, allowed_hosts, probe_lan)`。
   ツールのタイムアウトは 420 s 以上。

## タスク spec の上限 (オーケストレーターが root で検証・切り詰め)

task ≤ 4000 文字 / urls ≤ 5 (https, allowed_hosts 内) / allowed_hosts ≤ 10 (IP リテラル・.local/.lan 等は拒否) /
max_steps ≤ 8, max_llm_calls ≤ 6, max_tokens ≤ 32768 (既定 32768), max_seconds ≤ 1800 (既定 1200), page_chars ≤ 8000 / probe_targets ≤ 12。

## セキュリティ上の性質

- 資格情報は MMDS のみ (cmdline・シリアル・ログに出さない)、VM 破棄時に shred。ゲストは自己検査でキーらしき文字列を走査し件数のみ報告。
- シリアルから親へ戻るのは正規表現で検証済みのトークン (artifact_id, status, イベント) のみ。本文は ASG 経由のみ。
- 結果 (`result_untrusted`) は非信頼データ。親モデルは指示として扱わないこと。
- `fc.llm.chat` の `block_on_review=false` は運用判断 (無害な Web 本文の正規表現誤検知で止まるため)。risk ≥ 8 は遮断、出力ガードは有効。
- run ごとの識別子 (Rev13): `spawn_worker` は run ごとに新しいトークンを生成し、`/v1/runs` 登録時に `run_agents: {"fc_worker": <sha256>}` としてハッシュのみ渡す。
  ASG はそれを `fc_worker@<run_id>` として認証する。条件は 同じ `X-ASG-Run-Id`・run の有効期限内・失効 (再登録) 前 のみ。権限はテンプレート `fc_worker` と同じ。
  run 識別子は run 登録不可、静的トークンと同じハッシュは拒否、1 run あたり最大 4 件。
- canary: 囮の資格情報 (`asgctl canary add`) が依頼・応答・成果物に現れる、または囮ルートが呼ばれると、そのエージェントを失効。
  失効するのは発火した run の `fc_worker@<run_id>` のみ。他の run・親・以後の新しい run は影響を受けず、解除操作は不要。
  `spawn_worker` は `status: "canary_tripped"` と明示的なエラーを返す (結果は返さない)。テンプレート `fc_worker` 自体を失効させると全 run が止まる (緊急停止用)。

## 検証

- `python spawn_worker.py --task "..." --url https://example.com/ --probe-lan` → `orchestrator.teardown` が全て空、
  `worker_events` に `keyscan hits=0`、`neg_llm_bad_cred http=401`、`neg_llm_unregistered_run http=403`、LAN プローブは全て timeout。
- ASG 監査: `run_registration` → `fc.llm.chat allow (backend_model/upstream_model)` → `artifact stored` → 親の download → 失効。
- canary 演習: 囮ルートはルーティング系エンドポイント (`/v1/tasks` 等) で評価される。`/inspect` はルートを評価しないため囮ルートは発火しない。
- プロンプトインジェクション演習では、`fc.llm.chat` の入力ガードが公開テストページ (umage-ai canary-pages L1-L4) をモデル到達前に遮断した (risk 11-27)。
- ガード調整 (Rev14):
  - `fc.llm.chat` は `action_policy.read_only_model: true`。ツールを持たないモデル呼び出しなので、アクションガードは承認不可カテゴリ (秘密情報の持ち出し・プライベート/メタデータ宛先・危険なスキーム・検査上限・呼び出し側バックエンド指定) のみ評価する。`tools` 等のフィールドは拒否。
  - `llm_snippet_check`: 下げてよいパターン (tool_escalation, external_write, role_reassignment, hidden_instruction_marker, authority_laundering, long_base64/hex) が発火したとき、該当箇所の前後を非信頼データとして囲み、ツールなしのモデルに instruction / description / unknown を判定させる。description のときだけその所見を 0 にする。unknown・エラーは現状維持。秘密情報・宛先・スキーム・tool_hijack・decoded_instruction 等は下げない。判定は監査ログに (カテゴリ・判定・snippet の sha256・文字数のみ) 記録される。
  - 全文の LLM inspector は従来どおり後段で実行される。
- 出力切れ対策 (Rev15): モデル応答が `finish_reason=length` で切れた場合、JSON が完結していればそのまま使う。完結していなければ、呼び出し回数と時間 (残り 20 秒以上) に余裕があるときに 1 回だけ「200 語以内で final JSON のみ」と要約を再要求する。それも無理なら、取り出せた部分を `[TRUNCATED: …]` 付きで提出し、フッターに `truncated=1` を付ける。`fc.llm.chat` の `backend.max_tokens` は 32768。
- 思考出力の除去 (Rev15): 推論 (thinking) 型のモデルは `message.reasoning_content` に思考過程を返す。ワーカーはこれを使わないが、出力検査は応答全体を見るため、上限を上げて思考が長くなると、システムプロンプトへの言及などで `blocked_by_output_guard` になっていた。`fc.llm.chat` の `backend.drop_response_message_fields: ["reasoning_content"]` を指定すると、ASG はまず未加工の応答全体でカナリア検査を行い、その後で思考欄を取り除く。出力検査は取り除いた後の、実際にワーカーへ渡す内容にかける。指定できるのは `reasoning_content` / `reasoning` / `thinking` だけで (`content` は不可)、対象は `openai_chat_completions` 経路に限る。
- 長文生成向けの上限 (Rev16):
  - 出力上限: 既定・上限とも 32768 トークン。
  - 実行時間: 既定 1200 秒、上限 1800 秒。
  - モデル 1 回の呼び出し: ワーカーの HTTP タイムアウトは min(1000, 残り時間+15) 秒。ASG の `fc.llm.chat` `backend.timeout_seconds` は 1000。
  - VM の寿命: `ASG_FC_TIMEOUT=1920`。
  - spawn_worker: ssh タイムアウト 2400 秒 (`ServerAliveInterval=30` 付き)、ラン TTL 2700 秒。dsh の `toolCallTimeoutMs` は 2460000。
  - 目安: GLM-5.3-Flash で約 50 トークン/秒、32k トークンで約 11 分。llm-fleet 側は request/attempt timeout 1800 秒、コンテキスト長 500k 以上なので余裕がある。
  - 手順数とモデル呼び出し回数の上限は変えていない。

### テスト専用: 入力ガードの記録のみモード (Rev17)

目的: 実際のプロンプトインジェクションを読ませたとき、モデル自身がそれに従うかを測るためのライブテスト。

- **既定は無効。** `test_modes.input_guard_log_only.enabled` を `true` にしたときだけ使える。テスト後は必ず `false` に戻す。
- **有効化の条件。** 次をすべて満たすランだけが対象になる。
  - ランを登録するときに `test_mode: "input_guard_log_only"` と、空でない `reason` を付けている。
  - 登録者が `allowed_registrars` (例: `parent_mcp`) に含まれる。
  - ランの寿命が `max_ttl_seconds` 以下。
- **動作。** 対象ラン・対象経路 (`routes`、例: `fc.llm.chat`) では、入力ガードが本来なら遮断・要レビューにする内容でもモデルへ転送する。その際、`test_mode_input_guard_bypass` 監査イベントに検出内容 (カテゴリ・リスク・スキャン結果) を記録し、そのリクエストの以降の監査イベントにも `test_mode` を付ける。本文は記録しない。
- **これまで通り有効なもの。** 出力ガード、カナリア (リクエスト側・応答側)、アクションガード、ランの範囲、ランごとのワーカー ID、ホストの許可リスト。
- **途中で無効にする方法。** 設定で `enabled` を `false` にするか、ランを `test_mode` なしで登録し直す (失効させる)。どちらでも直ちに効く。
- **spawn_worker 側。** `test_mode` / `decoy_file` / `timeout` / `limits` は運用者のスクリプト専用の引数。MCP ツールは公開スキーマの項目 (task, urls, allowed_hosts, probe_lan) 以外を `unknown_arguments` で拒否する。
- **(Rev17c) 行動ガードも記録のみ。** 対象ランでは、モデルへ渡す前の行動ガード (`blocked_by_action_guard`) も記録のみになり、`test_mode_action_guard_bypass` を監査する。承認フロー (`approval_required`) とツール欄の拒否は従来どおり有効。
- **(Rev17c) 証拠ファイル。** `evidence_file` を指定すると、対象ランについて次のものだけを .80 のローカルファイルに保存する (ワーカーにも親にも渡さない)。テスト後に消すか隔離すること。
  - 入力ガード・行動ガードが本来止めたはずの一致箇所の前後 (最大 600 文字 × 12 件)。
  - 出力ガードが止めたモデル出力 (最大 4000 文字)。


## 警告付き抽出 (warn-and-extract) と出力ガード誤検知対策 (Rev18)

- **fetch アクションのクエリ文字列**: モデル応答が厳密に `{"action":"fetch","url":...}` のみで、URL が https・userinfo/ポート無し・
  ホストが登録時の `fetch_hosts` (spawn_worker が allowed_hosts から送る) に含まれる場合に限り `output_dlp:url_query` だけを外す。
  他の URL/DLP 検出はそのまま。route の `output_policy.allow_fetch_query_to_run_hosts: true` で有効。
- **出力側スニペット意図判定**: `llm_snippet_check.apply_to_output: true` で、モデル出力 (fc.llm.chat 応答とワーカー成果物) にも
  スニペット判定を適用。入力側の下げられるカテゴリに加え `*_dlp:local_path`、さらに `secret_exfiltration` /
  `ja_secret_exfiltration` / `local_secret_file_request` は **窓内にスキーム付き URL が無い場合のみ** 下げられる。
  実秘密・private/危険 URL・canary・fetch 以外の url_query は決して下げない。取得ページ (入力) 側の対象は従来どおり。
- **ワーカー警告**: ワーカーの final は `warnings:[{source,categories,description}]` を持てる。出典 URL と回答中の許可外 URL は
  `⚠️攻撃の可能性あり（開かないこと）hxxps://host[.]tld/...` に無害化。入力/アクションガードで止まったページは捨てて警告を残し続行、
  出力ガードで止まった応答は 1 回だけ書き直しを依頼する。
- **ASG 側警告**: `report_run_warnings: true` の route では、run ごとに検出カテゴリ・無害化した出典 URL・リスク・結果
  (blocked / allowed / test_mode_pass / quarantined_pass) のみを `run_warnings.jsonl` (run store と同じディレクトリ) に記録し、
  その run の成果物 manifest の `asg_warnings` に添付する。spawn_worker は `warnings_asg` として返す (ワーカーが警告を省いても親に届く)。
  ページ本文は保存しない。

### quarantined read (opt-in、既定 OFF)

- config `quarantined_read.enabled` + 登録時 `read_mode:"quarantined"` (parent のみ、spawn_worker の operator 引数のみ。MCP 非公開)。
- 対象 route は `openai_chat_completions` かつ `action_policy.read_only_model: true` に限定 (validator が強制)。
- 入力の検出が **すべて注入系** (prompt_injection / obfuscation / llm_inspector / input_dlp:local_path) で、リスクが
  `max_risk_score` 以下のときだけ、ツールの無いモデルへ通す。アクションガードの阻止も同条件で通す。秘密・DLP・境界・canary・出力ガードは全て有効のまま。
  通過は `quarantined_read_pass` として監査し、`asg_warnings` が必ず付く。証拠ファイルは書かない。
- トレードオフ: 注入文がモデルに届くので、モデルが従うリスク (誤った要約、許可ホスト内の余計な fetch) は残る。
  被害はツール無し・秘密無し・許可ホスト限定・出力ガード・使い捨て VM で抑える。結果は常に untrusted。
  既定の通常モードは従来どおり高リスクページをモデル前で止める (警告付きで他ページの情報は返る)。
