# asg-mcp（親エージェント用の MCP サーバー）

親エージェントが ASG を使うための、標準入出力（stdio）方式の MCP サーバー。`scripts/asg_mcp.py`（標準ライブラリのみ）。
設計は [docs/design/setup-and-connectivity.md](../../../docs/design/setup-and-connectivity.md) の §4。

## 何を守るか

- **トークンはモデルに見えない。** サーバーがファイルから読み、ツールの引数にも結果にも出ない。
- **ルート・権限・taint は設定で固定。** ツールの引数で選べない（引数に `route`、`capability` 等は無く、余計な引数は拒否）。
- **結果は ID・列挙値・件数・時刻だけ。** バックエンドが他の文章を返しても、親には渡らない（投影）。
- **本文を返すツールは無い。** 承認、解除、本文ダウンロードのツールも無い。自由文を返す唯一のツール（レビュー要約）は**既定で無効**で、
  有効にしても、リンクの無効化（`hxxps://`）、制御文字・双方向文字の除去、長さ制限が入り、`untrusted: true` が付く。
- **接続先はループバックの `http://127.0.0.1` / `localhost` のみ。** 別ホストの ASG へは SSH トンネルを使う（[tunnel/](../tunnel/README.md)）。

## ツール

| ツール | 既定 | 返すもの |
|---|---|---|
| `asg_inspect(text)` | 有効 | blocked / requires_review / risk_score / 検出件数 / 検出カテゴリ名 |
| `asg_artifact_status(artifact_id)` | 有効 | `unchecked` / `verified` / `needs_review` / `blocked` と作成時刻。`verified` は「スキャナーが何も見つけなかった」の意味で、内容の真偽や安全を保証しない |
| `asg_delegate_research(question, urls?)` | **無効**（隔離ランナーのルートを設定してから有効化） | run_id、task_id、artifact_id、状態、件数。Web の本文は返らない |
| `asg_receipts(limit?)` | `receipts_file` を設定したときだけ | 受領ID・時刻・判定・artifact_id（本文なし） |
| `asg_artifact_review_summary(artifact_id)` | **無効** | スキーマ固定の要約（未信頼データ） |

## 設定と登録

1. 設定ファイルを作る: `asg-mcp.example.json` をコピーして編集（**トークンの値は書かない。ファイルのパスだけ**）。
   トークンは `python scripts/asgctl.py secrets init ...` で作り、ASG 側には `token_sha256` だけを登録する。
2. 親エージェントの MCP 設定に、次のコマンドを登録する（stdio、1行1メッセージの JSON-RPC）。

   ```json
   { "mcpServers": { "asg": { "command": "python", "args": ["<repo>/scripts/asg_mcp.py", "--config", "<path>/asg-mcp.json"] } } }
   ```

   `mcpServers` の形式は Claude Code（`.mcp.json`）と Claude Desktop で使える。OSS のハーネス（opencode、Hermes Agent、pi、openclaw など）は
   設定の書き方が異なるので、各ハーネスの MCP（stdio）の登録方法に、上のコマンドと引数を当てはめる。
   **各ハーネスでの動作確認は未実施**（このサーバーは単体テストと、実物の ASG に対する確認のみ）。
3. 確認: `python scripts/asgctl.py verify --role parent --human`（トンネル経由で ASG に届くこと）。

## 親エージェントへの指示

[skill/asg-parent/SKILL.md](skill/asg-parent/SKILL.md) に運用規則がある。MCP のツール説明にも要点を入れてあるので、skill が読まれなくても守られる。
