# ハーネス別コネクター（asg-mcp の登録と検証）

OSS のエージェントハーネスから `asg-mcp`（[../mcp/README.md](../mcp/README.md)）を使うための、検証済みの設定の形。
検証は `scripts/harness_check.py`（使い捨ての ASG ＋ ローカルの OpenAI 互換モデル `http://localhost:9200/v1` の `GLM-5.3-Flash-EXL3`）。
各ハーネスで `asg_inspect` が**ちょうど1回**呼ばれ、ASG の監査ログに `inspect` が残り、スキャナーが `blocked`、モデルの回答も一致することを合格条件にしている。

```sh
python scripts/harness_check.py list
python scripts/harness_check.py run <opencode|pi|hermes|openclaw|dsh> [--model-url ...] [--model ...] [--keep]
```

| ハーネス | 接続方式 | 設定の置き場所（検証時） | ツールの限定 | 結果 |
|---|---|---|---|---|
| opencode 1.18 | stdio | `OPENCODE_CONFIG` の一時ファイル（`mcp.asg` と専用プロバイダー） | `permission` で bash・edit・write・webfetch を deny | 合格 |
| pi 1.1 | stdio | `PI_CODING_AGENT_DIR` の一時フォルダー（`mcp.json`、`models.json`） | `--no-builtin-tools` | 合格 |
| Hermes Agent | stdio | 専用の `HERMES_HOME`（`config.yaml` の `mcp_servers`） | `-t asg`（MCP のみ） | 合格 |
| OpenClaw 2026.9 | **HTTP**（`asg-mcp --http`） | 専用プロファイル `asgcheck`（`mcp set`、`config set`） | `tools.deny` ＋ `tools.alsoAllow: ["asg"]` | 合格 |
| DeepSeek Harness（dsh） | stdio | 専用の `DSH_HOME` とプロファイル（`cordis.patch.yml`） | bash・fs・web・サブエージェント等を `disabled: true` | 合格 |

いずれも**ユーザーのグローバル設定は変更しない**（一時または専用の場所だけを使う）。モデルの API キーは不要（ダミー値）。

## ハーネスごとの注意

- **OpenClaw:** エージェントが隔離セッション（別アカウント・別ファイルシステム）で動くため、ホストの Python を起動できない（`ENOENT`）。
  `asg_mcp.py --http 127.0.0.1:<port> --http-key-file <key>` を起動し、`transport: streamable-http` ＋ `Authorization: Bearer <key>` で接続する。
  ツールは `alsoAllow` に `asg` を入れないと見えない（ID は `mcp:asg:asg__asg_inspect`）。環境変数での状態の切り替えは効かないので `--profile` を使う。
- **Hermes:** 新しいデータルートでは依存パッケージの導入に数分かかる（検証では専用の `HERMES_HOME` を使い回す）。`.cmd` 経由のため、プロンプトに `|` 等のシェル記号を含めない。
- **dsh:** プロファイルは `cordis.patch.yml` のパッチ（`insert` と ID 指定の上書き）で作る。LLM は `dsh-llm-pi-ai` 経由でローカルの OpenAI 互換エンドポイントへ。
  `apiKeyEnv` が必要（ダミー値でよい）。公式の DeepSeek 経路（`llm-deepseek*`）は無効にする。
- **共通:** Windows の `.cmd` シムは引数を再解釈するので、検証用の文には `| & ;` を入れない。

## 本番に登録するとき

検証用の設定は一時的なもの。実際の登録は、各ハーネスの MCP 設定に、検証で使った形（`command`＋`args`、または HTTP の URL＋ヘッダー）を当てはめる。
**登録は設定の変更なので、人が承認してから行う。** HTTP の鍵は `asgctl secrets init --kind key` で作り、ハーネスの設定にだけ置く。
