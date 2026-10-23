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
max_steps ≤ 8, max_llm_calls ≤ 6, max_tokens ≤ 4096 (既定 3000), max_seconds ≤ 240, page_chars ≤ 8000 / probe_targets ≤ 12。

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
- 出力切れ対策 (Rev15): モデル応答が `finish_reason=length` で切れた場合、JSON が完結していればそのまま使う。完結していなければ、呼び出し回数と時間 (残り 20 秒以上) に余裕があるときに 1 回だけ「200 語以内で final JSON のみ」と要約を再要求する。それも無理なら、取り出せた部分を `[TRUNCATED: …]` 付きで提出し、フッターに `truncated=1` を付ける。`fc.llm.chat` の `backend.max_tokens` は 4096。
