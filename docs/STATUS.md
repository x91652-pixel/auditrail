# auditrail 實作狀態盤點（Phase 0 基線）

盤點日期：2026-10-14（重做；2026-10-13 的第一版建立在舊底 `1e8dc9c` 上）。基準：`origin/main` = `1f8749b`（已含 PR #3 `09f1c0e` 與 PR #2 `c2c0209`）。本檔所在分支 `phase-0-baseline-status` 只比該基準多這份文件與下列文件修正。

**這份文件只做一件事：把 README / SECURITY / ROADMAP 的每一項主張對照到實際程式碼與測試。**
沒有改任何程式行為；同一次變更中只有文件被修改（見第 7 節）。

> 範圍說明：第 1–3.5 節與 3.6 之後的盤點基線是 `origin/main`（已含 PR #2 與 PR #3）。第 3.5b 節與下方 H3/H4/H5/V9/V10 列反映的是 `hardening-fixes` 分支（`phase-1-secure-defaults` + `test-gaps-d7` 之上）的狀態，**這些變更尚未合併進 main**。
> 第 1 節測試數字是 `origin/main` 上的；`hardening-fixes` 上的數字見第 1b 節。

狀態圖例：

| 符號 | 意思 |
|---|---|
| ✅ | 已實作，且有測試直接驗證這項主張 |
| 🟡 | 已實作，但測試只涵蓋一部分（缺口寫在備註） |
| ⚠️ | 已實作，但沒有測試 |
| 📄 | 只有文件，程式碼裡沒有 |

---

## 1. 測試結果

| 套件 | 指令 | 通過 | 失敗 | 跳過 |
|---|---|---|---|---|
| Python（Rust 執行檔已建置） | `pytest -q -rs` | **253** | 0 | 0 |
| Python（Rust 執行檔不存在） | 同上，先把 `verifier/target/release/auditrail-verify(.exe)` 移走 | 247 | 0 | **6** |
| Rust verifier | `cd verifier && cargo test --locked --release` | 4（`robust` 2、`vectors` 2） | 0 | 0 |
| Rust dashboard | `cd dashboard && cargo test --locked` | 3 | 0 | 0 |
| Python ↔ Rust 互相比對 | 包含在 Python 套件內：`test_fuzz.py`（11）、`test_reader_agreement.py`（53）、`test_rust_verifier.py`（2）、`test_vectors.py`（17 個測試 = 15 組向量各一個 + 2 個檢查）、`test_policy_hash.py`（24，其中 Rust 部分見下） | 全過（有執行檔時） | 0 | 見下 |

各測試檔數量（合計 253）：`test_reader_agreement` 53、`test_anchor` 28、`test_v2_agents` 26、`test_policy_hash` 24、`test_edge_cases` 22、`test_logistics_sim` 20、`test_signed_evidence` 17、`test_vectors` 17、`test_fuzz` 11、`test_policy` 7、`test_agent_bridge` 6、`test_ledger` 5、`test_sandbox` 5、`test_cli` 4、`test_cli_v2` 4、`test_rust_verifier` 2、`test_demo` 1、`test_self_contained_demo` 1。

**注意（PR #2 新增的測試）：** `test_policy_hash.py` 裡有兩個測試只在找得到 Rust 執行檔時才會呼叫它（`if BINARY is not None:`），**找不到時不是跳過，而是只跑 Python 那一半並算「通過」**。所以沒有執行檔時的「247 通過」包含這兩個只驗了一半的測試；只有 `-rs` 看得到的 6 個才是被標記跳過的。

CI（GitHub Actions）在 PR #1 / #2 / #3 合併前全部成功；`verifier` job 會先建置 Rust 執行檔，因此 CI 上不會有跳過。

### 1b. `hardening-fixes` 分支上的測試數字（2026-10-14，Windows 11、Python 3.11、有 Rust 執行檔）

| 指令 | 結果 |
|---|---|
| `pytest -q -rs` | **529 通過、0 失敗、2 跳過**（`test_phase1_defaults.py:357` 與 `test_t010b_recorder.py:107`，各只在 POSIX 執行；另有只在 Windows 執行的 ACL 測試，在 POSIX 上會跳過）；共收集 531 個 |
| `cd verifier && cargo test --locked --release` | robust 2 通過、vectors 2 通過 |

沒有 Rust 執行檔時，`test_policy_hash.py` 的 9 個 Rust 對照測試會**明確 skip**（`pytest.skip`），不再算通過。Linux 與 Python 3.10 從未在本機執行。


## 2. 被跳過的測試

沒有任何測試被無條件跳過。跳過條件只有兩種：

| 條件 | 哪些測試 | 原因 | 啟用方式 |
|---|---|---|---|
| 找不到 Rust 執行檔 | `test_fuzz.py` 的 4 個（行 132、182、262、310）、`test_rust_verifier.py` 的 2 個 | 這些測試要拿 Python 與 Rust 的結果互相比對 | `cd verifier && cargo build --release`；測試會自動找 `verifier/target/release/auditrail-verify(.exe)`，或 PATH 上的 `auditrail-verify` |
| 找不到 `git` 執行檔 | `test_anchor.py` 中標 `needs_git` 的 git 見證測試 | 需要真的呼叫 git | 安裝 git（本次環境有，未跳過） |

注意：`test_reader_agreement.py` 與 `test_fuzz.py` 其餘測試沒有 Rust 執行檔也會跑，只是不做跨語言比對。
所以「Python 253 全過」不等於「Python 與 Rust 一致」——一致性只在執行檔存在時才被驗證。

## 3. 主張對照表

### 3.1 證據帳本（README「What it does」、SECURITY「What v0.2 does」）

| # | 主張 | 來源 | 程式碼 | 測試 | 狀態 | 備註 |
|---|---|---|---|---|---|---|
| E1 | 每筆紀錄串成雜湊鏈 | README、SECURITY 表 1 | `ledger.py` `record_hash`、`Ledger._append`；`verifier.py` `check_chain` | `test_ledger.py::test_record_and_verify`、`::test_tamper_in_middle_is_detected`；`test_edge_cases.py::test_inserted_record_is_detected`、`::test_reordered_records_are_detected` | ✅ | |
| E2 | 紀錄由記錄者金鑰以 Ed25519 簽章 | README、SECURITY 表 2 | `keys.py` `Signer`、`verify_sig`；`ledger.py` `_append` | `test_signed_evidence.py::test_signed_ledger_verifies_and_reports_what_is_not_covered`、`::test_a_different_key_is_rejected`、`::test_stripping_signatures_does_not_help_the_attacker` | ✅ | |
| E3 | 改一筆再重算所有 hash，v0.1 擋不住、v0.2 擋得住 | README | `verifier.py` `check_chain`（簽章檢查） | `test_signed_evidence.py::test_rewrite_and_rehash_passes_without_keys_but_fails_with_signatures`；`test_fuzz.py::test_rehashing_after_an_edit_never_gets_past_the_signatures`；向量 04；模擬攻擊 #15 | ✅ | 前提：驗證時有給 `--pubkey`；沒給時鏈仍通過（測試明確驗證這點） |
| E4 | 驗證器在沒給金鑰時，明說「簽章未檢查」 | README、SECURITY | `verifier.py` `verify_all` notes；`cli.py`；`main.rs` `not_checked` | `test_cli_v2.py::test_plain_verify_names_what_it_did_not_check`；`test_signed_evidence.py::test_signed_ledger_verifies_and_reports_what_is_not_covered` | ✅ | |
| E5 | 錨點（anchor）簽章 + 見證（witness），只拿見證副本即可證明被刪/被改 | README、SECURITY 表 3 | `anchor.py` `build_anchor`、`anchor_ledger`、`verify_anchors`、`verify_witness_file`、`FileSink`、`GitSink` | `test_signed_evidence.py::test_signed_anchor_in_witness_catches_whole_chain_rewrite_even_with_owner_anchors_deleted`、`::test_truncation_before_a_witnessed_anchor_is_detected`、`::test_forged_anchor_in_witness_is_rejected`；`test_anchor.py::test_git_witness_round_trip_is_ok` 等；向量 01–09 | ✅ | |
| E6 | 最後一個錨點之後的紀錄未被涵蓋，且會被如實回報 | README、SECURITY | `anchor.py` `_report(unanchored_tail=…)` | `test_anchor.py::test_verify_reports_tail_that_is_not_covered`；`test_signed_evidence.py::test_tail_after_the_last_anchor_is_reported_not_hidden` | ✅ | |
| E7 | 錨點與見證檔不含參數或結果 | README | `anchor.py` `build_anchor` | `test_anchor.py::test_anchors_and_witness_never_contain_args_or_results` | ✅ | |
| E8 | 參數與結果只存摘要，不存明文 | SECURITY | `ledger.py` `_digest` | `test_ledger.py::test_args_and_results_are_never_stored_in_plaintext`；`test_v2_agents.py::test_error_reason_is_a_digest_by_default_and_argument_text_never_lands_in_the_ledger` | ✅ | |
| E9 | 帳本在多行程同時寫入時鏈不壞 | ROADMAP「Done」 | `ledger.py` `_file_lock`（msvcrt / fcntl） | `test_signed_evidence.py::test_concurrent_writers_from_several_processes_keep_the_chain_intact` | 🟡 | 只在本次平台（Windows）跑過；fcntl 路徑沒有實測 |
| E10 | 記錄不含浮點數，任何語言可重現 hash | 格式規格 | `ledger.py` `_check_no_floats`；`_strict.py` | `test_signed_evidence.py::test_records_have_no_floats_so_any_language_can_reproduce_the_hash`；`test_reader_agreement.py` | ✅ | |

### 3.1b PR #2 新增：政策 hash 綁定與舊帳本處理

| # | 主張 | 來源 | 程式碼 | 測試 | 狀態 | 備註 |
|---|---|---|---|---|---|---|
| X1 | 每筆呼叫紀錄都帶完整政策 SHA-256（`policy_hash`） | PR #2 描述、規格 | `ledger.py` `CALL_FIELDS` / `call_fields`；`sandbox.py` `common`；`policy.py` `policy_hash` | `test_policy_hash.py::test_every_decision_carries_the_policy_hash`、`::test_recorder_path_keeps_the_hash` | ✅ | |
| X2 | 版本字串沒變但規則變了，證據看得出來 | PR #2 描述 | 同上 | `::test_same_version_string_but_changed_rules_is_visible_in_the_evidence`、`::test_the_hash_is_a_function_of_the_rules_not_of_key_order_or_whitespace` | ✅ | |
| X3 | 寫入端拒絕不是 64 位小寫十六進位（或 null）的值 | 規格 | `ledger.py` `call_fields` | `::test_the_writer_refuses_a_value_that_is_not_a_hash`（9 個參數） | ✅ | |
| X4 | 兩個驗證器都拒絕偽造的非 hash 值（即使 hash 與簽章都對） | 規格 | `verifier.py` `_check_fields`；`lib.rs` | `::test_both_verifiers_reject_a_forged_non_hash_even_when_it_is_correctly_hashed`（8 個參數）；向量 14 | 🟡 | Rust 那一半在沒有執行檔時**不會跳過也不會執行**（見第 1 節注意事項） |
| X5 | 真正的 v0.1 帳本得到 `LEGACY_FORMAT`，不是 `TAMPERED_LEDGER` | PR #2、SECURITY | `verifier.py:40`；`lib.rs:149`；`_strict.py` `is_legacy_text` | `::test_a_genuine_v01_ledger_is_not_called_tampered`；向量 15；夾具 `tests/fixtures/legacy_v01_ledger.jsonl`（由 v0.1 程式碼 `e37a7ed` 實際產生） | 🟡 | Rust 同上；夾具是真的，但只有 1 份、3 筆 |
| X6 | `auditrail verify --legacy-v01` 只檢查舊雜湊鏈並說明有多弱 | PR #2 | `cli.py:31,187`；`verifier.py` `verify_legacy_v01` | `::test_legacy_option_checks_the_old_hash_chain_and_says_how_weak_that_is`、`::test_cli_legacy_flag` | ✅ | **只有 Python**；Rust 驗證器沒有這個旗標（README/SECURITY 已寫明） |
| X7 | 沒有政策時，記錄者心跳寫 `policy_hash: null`（不是 `""`） | PR #2 | `recorder.py` | `test_policy_hash.py::test_recorder_path_keeps_the_hash`（第 87 行斷言 `beat["policy_hash"] is None`） | 🟡 | 測的是 `RecorderService` 類別；CLI 的 `serve()` 路徑沒有測 |

### 3.2 心跳與記錄者服務

| # | 主張 | 來源 | 程式碼 | 測試 | 狀態 | 備註 |
|---|---|---|---|---|---|---|
| H1 | 心跳列出包裝的工具、政策 hash、攔截 vs 已記錄呼叫數 | README、SECURITY 表 4 | `sandbox.py` `Guard.heartbeat`；`ledger.py` `record_heartbeat`；`verifier.py` `check_heartbeats` | `test_signed_evidence.py::test_tool_and_policy_changes_are_listed`、`::test_calls_intercepted_but_not_recorded_are_flagged`；`test_v2_agents.py::test_guard_heartbeat_reports_intercepted_vs_recorded` | ✅ | |
| H2 | 心跳空窗（`--max-gap`）會被回報；完全沒有心跳也算失敗 | README、SECURITY | `verifier.py` `check_heartbeats` | `test_signed_evidence.py::test_heartbeat_gap_is_reported`、`::test_no_heartbeat_at_all_fails_when_a_gap_limit_is_set` | ✅ | |
| H3 | 背景定期心跳（`Guard.start_heartbeats` / `stop_heartbeats`） | README 程式碼範例 | `sandbox.py` `start_heartbeats` / `stop_heartbeats` | `test_gaps_d7.py::test_h3_background_heartbeats_keep_arriving_and_the_final_one_is_written_on_stop`、`::test_h3_stop_without_final_writes_nothing_and_stops_the_thread`、`::test_h3_starting_twice_does_not_start_a_second_thread`、`::test_h3_can_be_restarted_after_a_stop`、`::test_h3_the_heartbeats_describe_the_wrapped_tools_and_the_ledger_verifies` | ✅ | T-009 補上；間隔 0.05 秒、有上限的輪詢。只在 Windows 實跑 |
| H4 | 記錄者服務定期寫心跳與錨點 | README | `recorder.py` `RecorderService._loop`、`heartbeat`、`anchor` | `test_gaps_d7.py::test_h4_the_loop_calls_its_function_at_the_interval_until_stopped`、`::test_h4_a_failing_beat_does_not_kill_the_loop`、`::test_h4_start_wires_the_heartbeat_loop_and_stop_writes_a_final_beat`、`::test_h4_anchor_writes_a_signed_anchor_that_verify_accepts_and_chains`、`::test_h4_the_periodic_anchor_loop_produces_a_verifiable_anchor` | ✅ | T-009 補上。`serve()` 預設的 300 秒錨定間隔本身沒測（測的是 `anchor_s=1`） |
| H5 | 記錄者是獨立行程，金鑰與帳本只在那邊，代理只能附加；收到停止訊號會寫最後心跳與錨點 | README、SECURITY | `recorder.py` `RecorderService`、`RemoteLedger`、`serve`；`cli.py recorder` | `test_gaps_d7.py::test_h5_a_separate_os_process_records_what_an_agent_appends`（真的子行程）、`::test_h5_the_stop_signal_makes_it_exit_cleanly_with_a_final_heartbeat_and_anchor`、`::test_h5_a_wrong_token_is_refused_by_the_separate_process`；類別層級另有 `test_v2_agents.py::test_recorder_holds_the_key_and_agent_side_can_only_append` 等 | ✅（Windows）／🟡（POSIX） | **停止訊號路徑在 POSIX（SIGTERM）從未實際執行過**，只在 Windows（CTRL_BREAK）驗證；Windows 上它曾因 `time.sleep(3600)` 收不到 SIGBREAK 而失敗，已於 `fbb77b3` 修正（改 0.5 秒短睡） |
| H6 | 記錄者拒絕沒有 token 的請求與非附加操作 | SECURITY | `recorder.py` `_handle` | `test_v2_agents.py::test_recorder_rejects_requests_without_the_token_and_non_append_ops` | ✅ | |
| H7 | 記錄者只綁 loopback | SECURITY | `recorder.py` `RecorderService.__init__` | `test_v2_agents.py::test_recorder_refuses_non_loopback_addresses` | ✅ | |

### 3.3 錨定與驗證的結果代碼

README「Anchoring」寫的是 7 種結果。實際 Python `verify`（含錨點）能回傳的有 10 種，README 少列 3 種（見第 6 節）。

| 狀態 | 程式碼 | 測試 | 狀態 |
|---|---|---|---|
| `OK` | `anchor.py` | `test_anchor.py::test_normal_anchor_then_verify_is_ok` | ✅ |
| `TAMPERED_LEDGER` | `verifier.py` `check_chain` | `test_anchor.py::test_rewriting_a_middle_record_is_detected_at_that_seq`、`test_ledger.py::test_tamper_in_middle_is_detected` | ✅ |
| `TAMPERED_ANCHOR` | `anchor.py:92,127,133,149` | `test_anchor.py::test_rewriting_any_anchor_line_is_tamper_anchor`、`::test_breaking_the_anchor_link_is_tamper_anchor`、`::test_malformed_anchor_line_is_tamper_anchor` | ✅ |
| `REWRITTEN` | `anchor.py:240,288` | `test_anchor.py::test_careful_rewrite_with_recomputed_chain_is_rewritten` | ✅ |
| `TRUNCATED` | `anchor.py:238,285` | `test_anchor.py::test_truncating_before_the_anchor_is_truncated`、`::test_missing_ledger_with_anchors_is_truncated` | ✅ |
| `SINK_MISMATCH` | `anchor.py:254` | `test_anchor.py::test_file_sink_content_changed_is_sink_mismatch`、`::test_git_witness_content_rewritten_by_owner_is_sink_mismatch` | ✅（僅 Python；Rust 驗證器沒有「sink」概念，只吃見證檔） |
| `SINK_UNREACHABLE` | `anchor.py:248,252,273` | `test_anchor.py::test_witnessed_anchor_without_its_sink_is_unreachable_not_ok`、`::test_git_witness_missing_repo_is_unreachable` | ✅（僅 Python） |
| `UNSIGNED_ANCHOR` | `anchor.py:119` | `test_signed_evidence.py::test_unsigned_v1_anchor_is_refused_when_signatures_are_required` | ✅ |
| `UNKNOWN_KEY` / `BAD_SIGNATURE` | `verifier.py`、`anchor.py` | `test_signed_evidence.py::test_a_different_key_is_rejected`、`::test_forged_anchor_in_witness_is_rejected`、向量 04、07 | ✅ |

其他驗證狀態：`UNSIGNED_RECORD`、`MALFORMED_RECORD`、`NO_HEARTBEAT`、`HEARTBEAT_GAP`、`UNRECORDED_CALLS` 都有程式碼與測試。`LEGACY_FORMAT`（PR #2）：Python `verifier.py:40`、Rust `lib.rs:149`，測試 `test_policy_hash.py::test_a_genuine_v01_ledger_is_not_called_tampered`、向量 15。

### 3.4 政策、代理間訊息、對帳、隔離

| # | 主張 | 來源 | 程式碼 | 測試 | 狀態 | 備註 |
|---|---|---|---|---|---|---|
| P1 | 同一 session 湊齊三類（資料存取 + 不可信輸入 + 對外通訊）就在執行前拒絕 | README、SECURITY 表 5 | `policy.py` `PolicyEngine.check` / `commit` | `test_policy.py::test_third_category_completes_trifecta_and_is_denied`、`test_edge_cases.py::test_categories_accumulate_across_different_tools_in_one_session`；模擬 #1、#2 | ✅ | |
| P2 | 被拒絕的呼叫不會執行 | README | `sandbox.py` `guarded_tool` | `test_sandbox.py::test_denied_call_never_executes_the_real_function`、`test_edge_cases.py::test_denied_call_is_never_executed_even_with_isolation` | ✅ | |
| P3 | 三類計算可跨 workflow（共用 `trace_id`） | README、SECURITY | `policy.py` `workflow_categories`、`inherit` | `test_v2_agents.py::test_sessions_sharing_a_trace_id_share_trifecta_state` | ✅ | |
| P4 | 三類計算可跨代理（簽章訊息帶著寄件者的類別） | README、SECURITY | `agent_bridge.py` `send_envelope` / `receive_envelope`；`sandbox.py` `receive_message` | `test_v2_agents.py::test_trifecta_split_across_two_agents_is_blocked`；`test_logistics_sim.py::test_v02_trifecta_split_across_agents_is_blocked_as_one_workflow`；模擬 #14 | ✅ | 靠 `trace_id` 傳遞；沒有訊息也沒有共用 `trace_id` 的 session 仍互相獨立（見模擬 #11） |
| P5 | 沒有連結的 session 行為與 v0.1 相同 | 程式碼註解 | `policy.py` | `test_v2_agents.py::test_unlinked_sessions_still_behave_like_v01` | ✅ | |
| P6 | 工具必須在代理的允許清單內 | README | `policy.py` `check` | `test_policy.py::test_tool_not_allowlisted_denied`、`::test_unknown_agent_falls_back_to_default_deny_all`；模擬 #4、#5 | ✅ | |
| M1 | 每個代理有自己的 Ed25519 金鑰；訊息可歸屬、綁定收件者 | README、SECURITY 表 6 | `agent_bridge.py` `send_envelope`、`receive_envelope`；`keys.py` `KeyRegistry` | `test_v2_agents.py::test_envelope_round_trip_and_receipt`、`::test_shared_key_style_impersonation_is_impossible`、`::test_tampered_payload_redirect_unknown_sender_and_replay` | ✅ | |
| M2 | 收據（receipt）綁定特定訊息 | README | `agent_bridge.py` `make_receipt` / `verify_receipt` | `test_v2_agents.py::test_receipt_for_another_message_is_rejected` | ✅ | |
| M3 | 逾時與重放會被擋 | SECURITY | `agent_bridge.py` `ReplayGuard`、`receive_envelope` | `test_v2_agents.py::test_stale_envelope_is_rejected`、`::test_replay_guard_forgets_old_nonces_so_memory_is_bounded`；`test_agent_bridge.py`；模擬 #7、#8 | ✅ | 重放保護只在記憶體（SECURITY 已寫明） |
| M4 | 被拒絕的訊息也寫成證據 | 程式碼 | `sandbox.py` `receive_message` | `test_v2_agents.py::test_rejected_messages_are_recorded_as_evidence` | ✅ | |
| M5 | v1 共享密鑰 HMAC 保留相容 | SECURITY | `agent_bridge.py` `sign_message` / `verify_message` | `test_agent_bridge.py`（6 個） | ✅ | |
| R1 | `auditrail reconcile` 找出只有一方記錄的訊息 | README、SECURITY 表 6 | `reconcile.py` `reconcile`；`cli.py` | `test_v2_agents.py::test_reconcile_finds_a_message_the_sender_never_recorded`、`::test_reconcile_finds_a_send_the_receiver_never_recorded`、`::test_reconcile_does_not_judge_agents_whose_ledger_was_not_given`；`test_cli_v2.py::test_reconcile_command` | ✅ | |
| I1 | `isolate=True`：子行程、環境變數允許清單、逾時 | README、SECURITY 表 7 | `sandbox.py` `_call_isolated`、`_isolated_env`；`_isolate_worker.py` | `test_v2_agents.py::test_isolated_env_is_an_allow_list_not_a_deny_list`；`test_sandbox.py::test_isolated_call_runs_in_subprocess_and_still_returns_real_result`；模擬 #9、#10 | ✅ | |
| I2 | 工具輸出無法偽造或破壞隔離結果 | ROADMAP「Done」 | `sandbox.py` `RESULT_MARKER` | `test_v2_agents.py::test_isolated_tool_that_prints_does_not_corrupt_its_result`、`::test_isolated_result_cannot_be_forged_by_tool_output` | ✅ | |
| I3 | 隔離「不是」安全沙盒 | README、SECURITY | — | — | 📄 | 這是一項**否定性**聲明，不需要測試；程式碼確實沒有檔案系統或網路限制 |

### 3.5 驗證器、規格、工具鏈

| # | 主張 | 來源 | 程式碼 | 測試 | 狀態 | 備註 |
|---|---|---|---|---|---|---|
| V1 | 獨立的 Rust 驗證器，單一離線執行檔，無網路 | README、SECURITY 表 | `verifier/src/lib.rs`、`main.rs` | `verifier/tests/vectors.rs`、`robust.rs`；`test_rust_verifier.py`；`test_vectors.py` | ✅ | 「獨立」= 另一種語言的實作，**同一作者**（SECURITY 已寫明） |
| V2 | 以同一組一致性向量測試兩邊（README 與 ROADMAP 寫法不同，見第 6 節） | README、ROADMAP | `docs/spec/vectors/`（15 組，`generate.py`；14 = 畸形 policy_hash、15 = 真正的 v0.1 帳本） | `test_vectors.py`（17 個測試 = 15 組向量各一個 + 2 個檢查）、`vectors.rs` | ✅ | |
| V3 | Python 與 Rust 以 Hypothesis 互相模糊測試 | README | — | `test_fuzz.py`（11）、`test_reader_agreement.py`（53） | ✅ | 需要先建置 Rust 執行檔（第 2 節） |
| V4 | 兩邊讀檔規則一致（UTF-8、換行、浮點、整數範圍、時間戳…） | SECURITY 版本史、規格第 2 節 | `_strict.py`；`lib.rs` | `test_reader_agreement.py`（53 個逐案測試） | ✅ | |
| V5 | `auditrail-verify` 可直接當命令使用 | README | `verifier/src/main.rs` | `test_rust_verifier.py`（用路徑呼叫） | 🟡 | **`pip install` 不會安裝這個命令**（`pyproject.toml` 只有 `auditrail`）；只有自己建置的 Rust 執行檔或 release 下載才有。README 沒說清楚（第 6 節） |
| V6 | 預先建置的驗證器執行檔 + SHA256SUMS + 出處證明 | README | `.github/workflows/release.yml` | 無（從未在 GitHub 上跑過） | ⚠️ | README 已寫明「尚未發布」；workflow 已隨 PR #3 合併進 main，但**從未在 GitHub 上執行過**（`gh run list --workflow release.yml` 無紀錄）；也沒有任何 tag 或 Release |
| V7 | 兩次乾淨建置位元組相同 | README | `release.yml` 的建置旗標 | 本機驗證過一次（同一台機器） | 🟡 | 跨機器相同**未驗證**，README 已如實寫明 |
| V8 | 公開格式規格 `docs/spec/evidence-format-v2.md` | README | 規格 + 向量 | `test_vectors.py` | ✅ | |
| V9 | `auditrail keygen` / `anchor --key` / `verify --pubkey --anchors --git-repo --witness-file --max-gap --json` | README | `cli.py` | `test_cli_v2.py::test_keygen_then_signed_anchor_then_verify_with_witness`（含 `--pubkey --witness-file --max-gap --json`）；`test_anchor.py::test_cli_json_output_for_verify_and_anchor`（`--anchors --json`）；`test_gaps_d7.py::test_v10_*`（`anchor --git-repo --key --push`） | 🟡 | **`verify --git-repo`（CLI）沒有任何測試**；git 見證只經由 Python API（`GitSink`）被測 |
| V10 | `anchor --push` 才會推送見證庫，且真的推送 | README、SECURITY | `anchor.py` `GitSink.push`；`cli.py` | `test_gaps_d7.py::test_v10_push_really_reaches_the_remote_and_the_remote_copy_verifies`（本機 bare repo；驗遠端檔案內容與 clone 後的 witness 驗證）、`::test_v10_a_later_anchor_is_pushed_too`、`::test_v10_without_push_the_remote_stays_empty`、`::test_v10_a_push_that_cannot_reach_its_remote_is_reported_not_swallowed`；`test_anchor.py::test_push_is_not_called_unless_requested` | ✅ | 只用本機 bare repo，沒有網路；沒有 git 時 skip。Linux 未實跑 |
| V11 | `GitSink` 發布失敗時不留本地錨點 | 程式碼 | `anchor.py` | `test_anchor.py::test_git_publish_failure_records_no_local_anchor` | ✅ | |
| V12 | 內建 demo、`lint` 可離線執行 | README | `_demo.py`、`cli.py` | `test_demo.py`、`test_self_contained_demo.py`、`test_cli.py::test_lint_ok` | ✅ | 本次手動重跑：`auditrail verify` 對 demo 帳本回 OK、竄改版回 TAMPER、`lint` 回 OK |
| V13 | Dashboard（Rust） | README（只提到 `cargo test`） | `dashboard/` | 3 個單元測試 | 🟡 | README 沒有描述 dashboard 的功能；只有 3 個測試，沒有端對端測試 |

### 3.5b phase-1 與之後新增的主張（分支 `phase-1-secure-defaults` → `test-gaps-d7` → `hardening-fixes`）

這一節的列**不在 origin/main**；它們屬於尚未合併的分支。`✅` 的條件是：有具名測試，且該測試真的斷言了該主張。

| # | 主張 | 程式碼 | 測試 | 狀態 | 備註 |
|---|---|---|---|---|---|
| S1 | strict 模式拒絕沒有任何類別的工具，帳本記錄 `unclassified_tool` | `policy.py` `check` | `test_phase1_defaults.py::test_strict_refuses_an_unclassified_tool_and_records_why`；`test_t006_labels.py::test_d2_empty_list_in_strict_mode_is_refused_and_recorded_as_unclassified` | ✅ | 空清單 `[]` 不算宣告（D-2），同一測試鎖住 |
| S2 | 非 strict 時行為不變，但包裝工具時發 `UnclassifiedToolWarning` | `sandbox.py` `guarded_tool` | `test_phase1_defaults.py::test_non_strict_keeps_the_old_behaviour_but_warns_at_wrap_time`、`::test_no_warning_when_the_tool_is_classified_or_strict` | ✅ | 警告只出現一次、在包裝時 |
| S3 | `state_change` + `enforce_state_change_after_untrusted`：同一 workflow 讀過不可信內容後拒絕 | `policy.py` `check` | `test_phase1_defaults.py::test_state_change_after_untrusted_input_is_refused_when_enabled`、`::test_state_change_rule_follows_the_workflow_not_just_the_session`、`::test_explicitly_allowed_state_change_tool_passes`、`::test_default_policy_evaluates_state_change_exactly_as_before`；模擬 #17 | ✅ | 只對**被標成 `state_change`** 的工具有效；標錯不會被發現（模擬 #19） |
| S4 | `SqliteReplayGuard`：多行程共享重放判斷，失敗時關閉 | `agent_bridge.py` | `test_phase1_defaults.py::test_two_processes_replaying_one_message_second_is_refused`、`::test_concurrent_processes_exactly_one_accepts`、`::test_sqlite_guard_fails_closed_when_the_store_is_unusable`、`::test_sqlite_guard_forgets_nonces_after_the_ttl` | ✅ | 只限同一台主機；Linux 未實跑 |
| S5 | 記錄者 token 以固定長度摘要比較（常數時間原語），非 ASCII token 可用 | `recorder.py` `_token_matches` | `test_phase1_defaults.py::test_token_is_compared_with_a_constant_time_primitive`、`::test_token_with_non_ascii_characters_is_accepted_when_correct`、`::test_non_string_token_is_just_wrong` | 🟡 | 測的是「呼叫了 `hmac.compare_digest` 且參數是 bytes」，**不是時間側通道本身**；沒有計時測試 |
| S6 | 記錄者在金鑰／帳本／錨點檔權限過寬，**或權限檢查本身跑不起來**時拒絕啟動（結束碼 2）；`--allow-loose-permissions` 降為警告（跑不起來的情形印 `NOT CHECKED`） | `recorder.py` `serve`；`_perms.py` | `test_t006_recorder_permissions.py::test_d4_serve_refuses_to_start_with_a_loose_key`、`::test_d4_the_flag_downgrades_the_refusal_to_a_warning_and_the_recorder_runs`、`::test_d4_a_loose_ledger_is_refused_too`；`test_t010b_recorder.py::test_d10_unchecked_refuses_to_start_by_default`、`::test_d10_the_flag_downgrades_it_to_a_not_checked_warning_and_it_starts`、`::test_d10_windows_powershell_failures_all_end_in_refusal`（3 種失敗）、`::test_d8_2_an_anchors_file_others_can_write_is_refused_and_the_flag_downgrades_it` | 🟡 | Windows 路徑用真的 `icacls`，PowerShell 不可用以 monkeypatch 模擬（沒有真的移除系統 PowerShell）。**POSIX 的真實檔案測試（`test_posix_check_on_a_real_file`）在 Windows 上被跳過、從未實跑**；POSIX 只有純函式 `posix_findings` 被測。Windows 檢查只看 Everyone/Users/Authenticated Users/Guests/Anonymous；通過不代表金鑰安全 |
| S7 | `internal` 與任何其他類別並用 → 載入期 `PolicyError`；呼叫端標籤與政策矛盾 → `PolicyError`；`check()` 對繞過者回 `label_conflict` | `policy.py` `label_conflict`、`check_call_site_labels` | `test_t006_labels.py::test_d3_internal_plus_any_other_category_in_the_policy_is_refused_at_load`（5 個參數）、`::test_d3_conflict_at_the_call_site_is_refused_when_the_tool_is_wrapped`、`::test_d3_call_site_label_that_contradicts_the_policy_is_refused` | ✅ | 單獨標 `internal` 的工具不會被檢查（模擬 #19） |
| S8 | 類別值必須是字串清單；`agents: {a: null}`、字串、None、數字、巢狀清單在載入期丟 `PolicyError`，含工具名與區段 | `policy.py` `_validate_structure`、`string_list`、`call_site_list` | `test_t010_policy_types.py::test_tool_category_values_must_be_a_list_of_strings`（9 個參數）、`::test_an_agent_section_that_is_null_or_not_a_mapping_is_refused_at_load`、`::test_call_site_categories_must_be_strings_in_a_list`（7 個參數） | ✅ | **沒有處理**類別名稱的大小寫、空白、拼字錯誤與未知類別（待 D-9） |
| S9 | 記錄者沒有 token／token 為空字串時警告並仍啟動 | `recorder.py` `serve` | `test_t010_recorder_token.py`（4 個測試） | ✅ | 紅階段只對「空字串」分支做過破壞驗證 |
| S10 | 在 Windows 上 `auditrail recorder` 可被 Ctrl+Break 停下並寫最後心跳與錨點 | `recorder.py` `serve` | `test_gaps_d7.py::test_h5_the_stop_signal_makes_it_exit_cleanly_with_a_final_heartbeat_and_anchor` | 🟡 | Windows ✅；**POSIX 的 SIGTERM 路徑未實跑**（程式碼同一條，但沒驗證） |
| S11 | `.gitignore` 排除 `*.key` 與 `keys/` | `.gitignore` | 無測試（以 `git ls-files -i -c --exclude-standard` 為空檢查） | 🟡 | 不是行為，是設定；`keys/` 同時隱藏旁邊的 `.pub` |
| S12 | 類別名稱必須是內建名稱（`data_access`、`untrusted_input`、`external_comm`、`state_change`、`internal`、`agent_to_agent`）或在頂層 `custom_categories` 宣告；其他寫法（大小寫、前後空白、`state-change`、拼錯）在載入與呼叫端包裝時拋 `PolicyError`，附最接近的已知名稱；strict 與否皆同 | `policy.py` `BUILTIN_CATEGORIES`、`_declared_categories`、`_validate_names`、`suggest_category`、`check_call_site_labels` | `test_t010b_names.py::test_d9_non_canonical_or_misspelled_names_are_refused_with_a_suggestion`（11 個參數）、`::test_d9_a_name_with_no_close_match_points_at_the_declaration_syntax`、`::test_d9_it_is_the_same_error_without_strict_mode`、`::test_d9_a_declared_custom_category_is_accepted_and_changes_the_policy_hash`、`::test_d9_custom_names_must_be_written_in_the_canonical_form`（7 個參數）、`::test_d9_call_site_labels_get_the_same_check`、`::test_builtin_set_is_exactly_what_the_code_defines` | ✅ | 名稱以 `fullmatch` 精確比對（T-015/N-1：之前用 `^…$`，結尾換行會通過；測試 `test_t015_n1_names.py` 含 `\n`、`\r`、`\x00`、不換行空白、YAML `|` 區塊純量，另有掃描 `src/` 的測試禁止裸 `$` 錨定）。宣告不等於審查：已宣告但錯誤的名稱照單全收；引擎對自訂類別沒有任何規則。隨簽章訊息來的類別只計數、不驗名稱（`::test_d9_categories_that_arrive_with_a_signed_message_are_not_policed_by_name`）。`agent_to_agent` 在程式碼中沒有對應常數，是 T-010b 依範例政策與使用者決定列為內建 |
| S13 | 同名工具在不同 agent 區段被標成不同類別，**或一個區段標了、另一個區段只允許（`allowed_tools`）卻沒標** → 包裝時 `PolicyError`（載入時不報；`[]` 與沒標視為相同） | `policy.py` `check_call_site_labels` | `test_t010b_names.py::test_d8_3_the_same_tool_labelled_differently_in_two_agent_sections_fails_when_wrapped`、`::test_d8_3_an_empty_label_in_one_section_and_a_label_in_another_is_a_difference_too`、`::test_d8_3_identical_labels_and_a_tool_listed_by_one_agent_only_are_fine`、`::test_d8_3_order_of_the_labels_does_not_matter`；`test_t015_n3_sections.py::test_n3_labelled_by_one_agent_and_allowed_unlabelled_by_another_is_an_error`（兩個方向 × strict／非 strict）、`::test_n3_the_exact_scenario_from_the_review_cannot_wrap`、`::test_n3_a_default_section_label_without_an_agent_label_is_an_error`、`::test_n3_identical_labels_everywhere_pass`、`::test_n3_a_single_section_that_mentions_the_tool_passes`、`::test_n3_the_shipped_example_policy_and_the_simulation_policies_are_unaffected` | ✅ | 只在 `Guard.guarded_tool` 包裝時檢查；直接用 `PolicyEngine.check` 不檢查（`test_t015_known_limits.py` 釘住）。T-006 的說法「已如此」不完全正確，T-010b／T-015 才補齊 |
| S14 | `internal` 與已宣告的自訂類別並用 → 載入期 `PolicyError` | `policy.py` `label_conflict` | `test_t010b_names.py::test_d8_1_internal_with_a_declared_custom_category_is_an_error` | ✅ | |
| S15 | Windows 權限檢查：PowerShell 結束碼 0 但無可解析 ACE，**或有任何一行提到廣泛群組（SID 或名稱）卻不是格式正確的項目**（R-1／N-4），整個檔案視為 `unchecked`（記錄者預設拒絕啟動），不再當作「沒問題」 | `_perms.py` `parse_acl_lines`、`unparsed_broad_lines`、`permission_findings` | `test_t015_n2_acl.py`（空／垃圾／只有表頭）；`test_t017_acl_malformed.py::test_r1_each_malformed_shape_makes_the_file_unchecked`（11 種畸形行）、`::test_r1_a_tight_acl_with_unrelated_noise_still_passes`、`::test_r1_a_well_formed_broad_entry_is_still_loose_not_unchecked`、`::test_r1_the_recorder_refuses_on_a_malformed_line_and_the_flag_downgrades_it` | 🟡 | 輸出以 monkeypatch 注入，沒有在真的壞掉的 PowerShell 上試過；只在 Windows 實跑。**不提到廣泛群組的畸形行仍被忽略**；檢查範圍仍不含父目錄與授予單一帳號的 ACE；**CI 發現（T-019/T-020）**：從 PowerShell 7 啟動時子行程 5.1 的 `Get-Acl` 模組載入失敗 → 所有檢查變 `unchecked`。修正：不用模組 cmdlet（`[IO.File]::GetAccessControl`）、子行程環境移除 `PSModulePath`、以系統路徑啟動 5.1；測試 `test_t020_powershell_isolation.py`（含「Get-Acl 被遮蔽成會丟例外的函式」的本機重現）、`test_t019_diagnostics.py`。**本機沒有 PowerShell 7，無法證明 CI 轉綠** |
| S16 | 已知限制被釘住：YAML 重複鍵後者生效不報錯；`PolicyEngine.check` 單獨使用不做跨區段檢查 | — | `test_t015_known_limits.py`（2 個測試） | ✅ | 這是在斷言「限制仍存在」；修掉時測試會失敗，需同步改 SECURITY.md |
| S17 | `.pub` 公鑰檔 Python 與 Rust 用同一規則：去掉前後空白後必須恰為 64 個十六進位字元（大小寫皆可）；內嵌空白／換行、`0x`、奇數長度、31／33 位元組皆拒絕 | `keys.py` `parse_public_hex`、`load_public_keys`；`lib.rs` `parse_pubkey_hex` | `test_t017_pubkey_files.py::test_r2_python_accepts_exactly_the_key_files_the_rule_allows`（20 種）、`::test_r2_python_and_rust_agree_on_every_variant`（20 種） | ✅ | Rust 對照在沒有執行檔時明確 skip。**私鑰檔（`Signer.from_file`）仍用寬鬆讀法**，由 `::test_r2_the_signing_key_file_loader_is_still_lenient_and_is_reported_not_changed` 釘住；Rust 的 trim 與 Python 的 `str.strip()` 不同（後者多去掉 U+001C–U+001F），所以用明確的字元集 |


### 3.6 SECURITY.md「does NOT do」清單

這一節的每項都是**否定性聲明**。逐項確認程式碼裡確實沒有對應功能（即聲明為真）：

| 聲明 | 檢查結果 |
|---|---|
| 無法證明未包裝工具沒有被呼叫 | 為真。心跳只列包裝過的工具（H1） |
| 最後錨點之後的紀錄未涵蓋 | 為真，且驗證器會回報筆數（E6） |
| 記錄者主機或金鑰被攻破就無效 | 為真，沒有 KMS/TPM 整合 |
| 見證必須獨立 | 為真，沒有強制機制 |
| 沒有可信時間（RFC 3161） | 為真，程式碼中沒有 |
| 沒有加密保存參數 | 為真 |
| 不偵測提示注入 | 為真 |
| 類別由使用者標註；無外部通訊標籤的寫入動作不會被擋 | 為真；模擬 #3 實際示範 |
| 沒有連結的 session 互相獨立 | 為真；模擬 #11 實際示範 |
| 重放保護只在記憶體 | 為真（`ReplayGuard`） |
| `isolate=True` 不是沙盒 | 為真 |
| 無供應鏈驗證、記憶體污染偵測、連鎖失效控制 | 為真，程式碼中沒有 |
| 無隱寫偵測 | 為真 |

### 3.7 ROADMAP「Done in v0.2」

ROADMAP 列的 9 項（簽章、記錄者服務、心跳、錨點、Rust 驗證器、trifecta workflow、per-agent key/receipt/reconcile、隔離環境允許清單與輸出防偽、錯誤文字摘要與並行寫入）都已在上表對應。
唯一的**數字錯誤**：「ten conformance vectors」——實際是 15 組（見第 6 節）。

## 4. 攻擊模擬（`python -m examples.logistics_sim.run`）

結果（2026-10-14 在 `origin/main` 上重跑，與第一版相同）：正常營運 9/9 放行；攻擊 16 項，13 項防禦成功（被擋下或偵測到），3 項為文件化的已知缺口；全部符合預期；日誌 39 筆、雜湊鏈完整。

| # | 攻擊 | 結果 | 預期 | 分類 | 與 SECURITY.md 一致？ |
|---|---|---|---|---|---|
| 1 | 間接提示注入 → 個資外洩 | BLOCKED | BLOCKED | 擋下（trifecta） | 一致 |
| 2 | 惡意承運商資料 → 出貨清單外寄 | BLOCKED | BLOCKED | 擋下（trifecta） | 一致 |
| 3 | 惡意承運商資料 → 出貨改道到攻擊者站點 | ALLOWED | ALLOWED | **已知缺口**：寫入動作沒有外部通訊標籤 | 一致（SECURITY「About the policy」第 2 點） |
| 4 | 客服代理嘗試退款（越權） | BLOCKED | BLOCKED | 擋下（允許清單） | 一致 |
| 5 | 倉儲代理讀客戶個資（跨角色） | BLOCKED | BLOCKED | 擋下（允許清單） | 一致 |
| 6 | 偽造財務代理的核准訊息 | BLOCKED | BLOCKED | 擋下（簽章） | 一致 |
| 7 | 重放核准訊息 | BLOCKED | BLOCKED | 擋下（nonce） | 一致 |
| 8 | 一小時前簽的過期訊息 | BLOCKED | BLOCKED | 擋下（新鮮度視窗） | 一致 |
| 9 | 沙盒工具偷環境變數裡的 API 金鑰 | CONTAINED | CONTAINED | 擋下（環境允許清單） | 一致；注意只涵蓋環境變數，不含檔案（SECURITY 已寫） |
| 10 | 工具卡住（DoS） | CONTAINED | CONTAINED | 擋下（逾時） | 一致 |
| 11 | 三類拆在兩個 session | ALLOWED | ALLOWED | **已知缺口**：無共用 `trace_id`、無訊息連結 | 一致（SECURITY「Workflow tracking needs the link」） |
| 12 | 竄改一筆「拒絕」改成「允許」 | DETECTED | DETECTED | 偵測到（雜湊鏈） | 一致 |
| 13 | 悄悄刪掉最後一筆 | NOT DETECTED | NOT DETECTED | **已知缺口**：沒有錨點時偵測不到 | 一致（SECURITY「Records after the last anchor」） |
| 14 | 三類拆在兩個代理，以簽章訊息傳遞 | BLOCKED | BLOCKED | 擋下（workflow 追蹤） | 一致 |
| 15 | 竄改 + 重算整條雜湊鏈 | DETECTED | DETECTED | 偵測到（簽章），**需要給 `--pubkey`** | 一致；模擬明確標示「鏈本身仍通過」 |
| 16 | 有見證錨點之後刪掉尾端 | DETECTED | DETECTED | 偵測到（TRUNCATED） | 一致 |

SECURITY 與模擬的**不一致處**：沒有行為上的不一致。只有一處文字過時：模擬 #3 的「已知限制」說明寫「not in v0.1」（`examples/logistics_sim/scenarios.py:193`），應為「not in v0.2」。這是程式碼中的字串，本次依「只改文件」的規則沒有動，列在第 6 節。

兩點限制要讓讀者知道：
- #12、#15 的「偵測到」是在模擬自己控制的條件下（它知道記錄者金鑰、也有見證）。真實部署中，這取決於金鑰與見證是否真的放在操作者拿不到的地方。
- #3、#11 之所以「通過」是因為預期值被設成 ALLOWED。這是**誠實記錄缺口**，不是防禦成功；匯總的「13 / 13」不應被讀成「16 項全擋下」。

## 5. 版本字串

| 位置 | 現在 | 判斷 |
|---|---|---|
| `pyproject.toml` / `verifier/Cargo.toml` / `auditrail.__version__` | 0.2.0 | 一致 |
| README 徽章、Status、標題 | v0.2 | 一致 |
| **GitHub repo 簡介**（Settings → About） | 「…(v0.1 proof of concept)」 | **不一致**；這是 GitHub 設定，不在 repo 檔案內。已列出修正指令，但沒有執行（對外可見的變更，需要你同意） |
| `docs/x-announcement.md` | 全文寫 v0.1 | 這是尚未發布的 X 貼文草稿，內容是 v0.1 時的描述；已在檔首加註「草稿反映 v0.1，發布前需依 v0.2 重寫」 |
| `dashboard/Cargo.toml` | 0.1.0 | 獨立元件，版本號自成一套；不視為錯誤，但需要決定是否與主版本同步 |
| `examples/logistics_sim/scenarios.py:8,193,345,357` | 文字提到 v0.1 | 多數是在談「v0.1 的攻擊/行為」，語意正確；只有第 193 行過時（見第 4 節） |

修正 repo 簡介的指令（**尚未執行**）：

```bash
gh repo edit x91652-pixel/auditrail --description "Verifiable evidence layer for AI agents: signed, anchored audit trails and a lethal-trifecta policy guard (v0.2, early)"
```

## 6. README / SECURITY / ROADMAP 與實際不符之處

| # | 位置 | 說法 | 實際 | 處理 |
|---|---|---|---|---|
| D1 | README「Evidence the operator cannot quietly rewrite」 | `auditrail verify ... with the same flags in Python`，flag 寫 `--witness` | Python 的旗標是 `--witness-file`；`--witness` 只有 Rust 驗證器有 | 已改文件 |
| D2 | README 同節 | `auditrail-verify evidence.jsonl ...` 彷彿裝好就能用 | `pip install` 只安裝 `auditrail`；`auditrail-verify` 是 Rust 執行檔，要自己建置或下載 | 已改文件 |
| D3 | README「Anchoring」 | 引用 `auditrail-docs/錨定協定.md` | 該檔案不在 repo 內（目錄不存在）。`anchor.py` 的 docstring 與 `tests/test_anchor.py` 的 docstring 也引用同一路徑 | README 已改指向 `docs/spec/evidence-format-v2.md`；兩處 docstring 屬程式碼，未動 |
| D4 | README「Anchoring」 | `verify --anchors` 結果為 7 種 | 實際還有 `UNSIGNED_ANCHOR`、`UNKNOWN_KEY`、`BAD_SIGNATURE` | 已改文件 |
| D5 | ROADMAP「Done in v0.2」 | 「ten conformance vectors」 | **15 組**（PR #2 把向量從 13 組增為 15 組） | ROADMAP 目前寫「thirteen」，**已再次過時**；本卡範圍不含 ROADMAP.md，待指示 |
| D6 | README Quickstart | `auditrail verify examples/demo_ledger.jsonl` 暗示檔案在 repo 內 | 這些檔案由 demo 產生，且被 `.gitignore` 的 `*.jsonl` 排除，新 clone 沒有 | 已改文件（註明先跑 demo） |
| D7 | SECURITY 開頭 | 「Every claim in the 'does' column has a test」 | 絕大多數成立，但 H3（背景心跳）、H4（記錄者週期迴圈）、H5（真的獨立行程）、V10（真的 push）只被部分測試或沒被測 | **不改 SECURITY 措辭**——這是需要你決定的主張；已在第 3 節列出缺口，建議補測試而不是削弱文字 |
| D8 | `examples/logistics_sim/scenarios.py:193` | 「not in v0.1」 | 應為 v0.2 | 程式碼字串，未動 |
| D9 | README Status | 「253 Python tests」 | 數字正確（PR #2 已更新） | 無需處理 |

## 7. 本次變更（git diff 只含文件）

- 新增 `docs/STATUS.md`（本檔）
- 修改 `README.md`：D1、D2、D3、D4、D6
- 修改 `ROADMAP.md`：D5
- 修改 `docs/x-announcement.md`：檔首加註

沒有修改任何 `.py`、`.rs`、`.toml`、`.yml`。

## 8. 可重現的指令

在 repo 根目錄、已 `pip install -e ".[dev]"` 的環境中執行（Windows 用 `.venv\Scripts\...`）：

```bash
# Python 全套（含 Rust 比對，需先建置執行檔）
cd verifier && cargo build --release --locked && cd ..
pytest -q -rs

# 不含 Rust 比對的情形：先把 verifier/target/release/auditrail-verify(.exe) 移走再跑，應得 247 passed, 6 skipped

# Rust
cd verifier  && cargo test --locked --release
cd dashboard && cargo test --locked

# 更深的模糊測試
AUDITRAIL_FUZZ_EXAMPLES=500 pytest tests/test_fuzz.py -q

# 一致性向量（重新產生後應與已提交的檔案相同）
python docs/spec/vectors/generate.py && git diff --stat docs/spec/vectors

# 攻擊模擬
python -m examples.logistics_sim.run

# demo 與 CLI 冒煙測試
auditrail demo
auditrail verify examples/demo_ledger.jsonl
auditrail verify examples/demo_ledger_tampered.jsonl   # 應回報 TAMPER，exit code 1
auditrail lint policies/example_policy.yaml
verifier/target/release/auditrail-verify examples/demo_ledger.jsonl

# 本次文件變更只含文件
git diff --stat
```

## 9. 這份盤點沒有證明的事

- 沒有證明 `release.yml` 能在 GitHub 上成功：PR #3 已合併，但 `gh run list --workflow release.yml` 沒有任何執行紀錄（合併前的 CI 不會跑 release 流程）。
- 沒有證明跨機器可重現建置。
- Intel macOS 執行檔沒有被執行過。
- Linux / macOS 上的檔案鎖（`fcntl`）、`GitSink` 真實 push 路徑沒有被本次環境測到。
- 兩個驗證器出自同一作者；一致性測試只能證明「兩份實作彼此一致」，不能證明「規格正確」。
- 測試通過不代表真實部署中金鑰與見證放對了地方。
