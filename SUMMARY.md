# SUMMARY — Lofron レビュー検証済み指摘の修正 (2026-10-24)

ブランチ: `rev22-review-fixes-lofron` (main `0eb2d0b` から分岐)
対象: `_review_lofron_2026-10-24.md` の検証済み指摘のうち、本タスクで指示された 7 項目。

## 修正一覧

### 1. quarantined_read が action guard の拒否を解除する (gateway.py `handle_routed_request`)

- **修正前**: `quarantine_ok` が真だと `blocked_by_action_guard` を所見カテゴリに関係なく握りつぶし、private/LAN URL・メタデータ・危険スキーム・caller 指定バックエンド・検査上限超過まで転送していた。
- **修正後**: action guard の拒否は **test mode のときだけ** log-only (従来仕様どおり)。quarantined read は解除しない。隔離例外は入力ガードのみ (`quarantine_eligible`: 注入系カテゴリかつ risk ≤ max_risk_score)。
- 到達不能になった `quarantined_read_action_pass` 監査経路は削除。`docs/guides/test-modes.md` の「Still enforced」行を実装と一致するよう明確化。

### 2. snippet check が先頭 2 件のみ判定 / 判定パーサの緩さ (proxy.py)

- **修正前**: `max_matches_per_finding`(既定 2) 窓だけが全て description なら所見を 0 点化。3 件目以降は未判定のまま格下げ対象。また `parse_snippet_verdict` は文中に判定語が 1 語あれば受理 ("not a description" → description)。
- **修正後**: 格下げには **パターンの全一致** を検査して全て description であることが必要。`max_checks` 予算を超える一致が残る場合は **フェイルクローズ** (格下げしない、呼び出しもしない)。判定は 1 語の完全一致のみ受理し、否定文・余分な文章・複数判定語・未閉鎖 think タグは `unknown` (元の判定を維持)。`max_matches_per_finding` は廃止 (既存 config では受理のみ)。

### 3. リダイレクト先が送信後にしか検査されない (worker_agent.py)

- **修正前**: urllib が内部でリダイレクトを追い、完了後の `geturl()` ホスト確認のみ。拒否対象ホストへの接続自体は発生済み。
- **修正後**: `AllowlistRedirectHandler` が **リダイレクト先をリクエスト送信前に検証** (`url_allowed`: https・許可ホスト・userinfo 無し・ポート 443/既定、不正ポートは拒否)。不許可なら `redirect_not_allowed` として結果に記録し、接続しない。初期 URL も同じ規則で検査。

### 4. モデル呼び出しの per-run 上限なし (gateway.py)

- **修正前**: 上限はワーカー側 `max_llm_calls` のみ (アドバイス的)。侵害されたワーカーは守れない。
- **修正後**: `run_model_quota.enabled` / `run_model_quota.max_model_calls_per_run` (既定 200) を追加。`run_id` 付き chat-completions を全ルート横断でカウントし、上限到達で `429 run_model_quota_exceeded`。ガード処理より前で拒否し、**実際に転送された呼び出しのみ** カウント。`run_id` 無しの呼び出しは影響なし。カウンタはメモリ内 (再起動でリセット、run 期限で窗口は自然消滅)。

### 5. gc_runs が失効済み資格情報を復活させる (gateway.py)

- **修正前**: 期限切れレコードを個別に削除するため、spawn_worker 方式の失効 (短期 TTL での再登録・latest record wins) が先に GC されると、失効前の有効な旧レコードが残り、`run_agents` の per-run 資格情報が **復活** し得た。
- **修正後**: 「最新の有効レコードが期限切れ」の run_id は **全レコードを削除**。失効済み run は何も残らない。最新レコードが有効な run (TTL 延長など) の旧レコードは保持。不正行・未パース行は従来どおり保持。

### 6. host-network.sh と docs/guides/reverse-tunnel.md の不整合

- **修正前**: input チェーンが bridge 発の新規接続を全 drop し、トンネル終点 `BRIDGE_IP:ASG_PORT` への到達がドキュメントと矛盾。
- **修正後**: input チェーンに `iifname $WBR ip daddr $BRIDGEIP tcp dport $ASG_PORT accept` を追加 (トンネル終点)。`ASG_IP:ASG_PORT` の forward 許可は「ASG ハブを LAN で直接運用する場合の例外 (トンネル構成では未使用)」としてコメント・ドキュメント化。
- **意図的に実施していないこと**: ワーカーの外向き (NAT) egress を ASG のみに制限するロックダウンは **入れない** (ユーザ決定により、ワーカーは自由な外向きアクセスを維持)。`ip saddr $WNET accept` / masquerade は変更なし。

### 7. fc-worker.env が root で source される / assert による検査 (asg-fc-worker)

- **修正前**: `. /etc/asg/fc-worker.env` で root シェルコードとして実行 (所有 UID のみ確認)。spec 検査は `assert` (`python -O` で消える)。
- **修正後**: env は **データとして解析** (`load_fc_worker_env`): 既知 `ASG_FC_*` キーのみ・`KEY=VALUE` (前後の任意引用符、値後の空白＋`#` コメントは許可)・展開や置換なし・許可文字集合外は fail-closed。root 所有に加え **ファイルと親ディレクトリが group/other 書込可なら起動拒否**。spec 検査は明示的な if + `bad()` (`SystemExit`) に置換し、ポート表記の例外も明示処理。

## テスト

- 追加/修正した回帰テスト:
  - `tests/test_gateway.py::ReviewFixRegressionTests` — quarantined read で action guard がブロックを維持すること (X-Target-URL が 403 `blocked_by_action_guard`、注入は従来どおり隔離通過)、gc_runs が失効 run の全レコードを削除して復活を防ぐこと・TTL 延長 run を保持すること、per-run モデル呼び出し上限 (429・ガード拒否はカウントしない・run_id 無しは影響なし)・config 検査。
  - `tests/test_guard_tuning.py::SnippetCheckTests` — 全一致の判定 (3 件目の指示で格下げされない)・全件 description なら格下げ・予算超過でフェイルクローズ・判定パーサの完全一致。
  - `tests/test_fc_worker_agent.py::WorkerAgentRedirectTests` — `url_allowed` 規則・不許可リダイレクト先を送信前に拒否・許可先は追従・fetch が `redirect_not_allowed` を返す・初期 URL 不許可で未接続。`OrchestratorHardeningTests` — env を source しない・権限チェック・assert 不使用・env 例ファイルがパーサ規則に適合。
- **ローカル結果**: `python -m unittest discover -s tests` — 393 テストのうち、本修正で追加したテストを含め全て成功。失敗は 12 件で **すべて main でも再現する環境起因**:
  - `test_canary_ops` (4) / `test_incident_bundle` (5) / `test_asgctl_ops` (2) — `make_private` が icacls `/inheritance:r` でサンドボックス実行ユーザ自身のアクセスを剥がすため (Windows サンドボックス環境固有)。
  - `test_vm_presets::test_render_seed_fills_every_placeholder` — テスト内の bash 呼び出しがこのサンドボックスで使用不能 (シグナルパイプ作成に失敗)。CI (ubuntu-latest) では実行可能。
  - 加えて、このサンドボックスでは `tempfile` が 0700 で作るディレクトリにアクセスできないため、テスト実行時のみ workspace ローカルの `sitecustomize.py` で mkdtemp を置換して確認した (リポジトリには入れない)。
- `config.example.json` / `schemas/config.schema.json` / `examples/config.fc-worker.fragment.json` に `run_model_quota` を追加し `validate-config` 成功。

## 明示的に見送ったこと / スコープ外

- **ワーカー egress の ASG-only 化** (NAT/外向きの制限): ユーザ決定により意図的に見送り。host-network.sh は NAT 許可を維持。
- レビューの他の指摘 (fetch クエリ緩和の対象 URL 結び付け、multipart 打ち切り所見化、run scope の fail-closed 化、成果物の verified_with_warnings 分離、TOCTOU/世代固定、Windows ACL・実機試験など) は本タスクの 7 項目に含まれず未実施。
