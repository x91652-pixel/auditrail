//! auditrail dashboard backend.
//!
//! Thin Rust HTTP layer around the existing Python `auditrail` tool.
//! Integrity verification and policy validation are delegated to the
//! `auditrail` CLI so there is only one implementation of the rules.
//! Rust reads the evidence log and policy file for display.

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::{path::PathBuf, process::Command, sync::Arc};

const INDEX_HTML: &str = include_str!("../frontend/index.html");

struct Config {
    root: PathBuf,
    auditrail_bin: String,
}

#[tokio::main]
async fn main() {
    let default_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let cfg = Arc::new(Config {
        root: std::env::var("AUDITRAIL_ROOT").map(PathBuf::from).unwrap_or(default_root),
        auditrail_bin: std::env::var("AUDITRAIL_BIN").unwrap_or_else(|_| "auditrail".to_string()),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/ledger", get(ledger))
        .route("/api/verify", get(verify))
        .route("/api/policy", get(policy))
        .with_state(cfg);

    let addr = std::env::var("AUDITRAIL_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("無法綁定 {addr}：{e}"));
    println!("auditrail dashboard 已啟動：http://{addr}");
    axum::serve(listener, app).await.expect("server error");
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

fn ledger_path(cfg: &Config) -> PathBuf {
    cfg.root.join("examples").join("demo_ledger.jsonl")
}

fn policy_path(cfg: &Config) -> PathBuf {
    cfg.root.join("policies").join("example_policy.yaml")
}

fn bin_missing(cfg: &Config, e: std::io::Error) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!(
            "無法執行 auditrail 指令（{}）：{e}。請確認已安裝，或設定環境變數 AUDITRAIL_BIN",
            cfg.auditrail_bin
        )})),
    )
        .into_response()
}

/// Parse a JSONL evidence log. Blank and malformed lines are skipped.
fn parse_records(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// GET /api/ledger — every record in the evidence log, in order.
async fn ledger(State(cfg): State<Arc<Config>>) -> axum::response::Response {
    let path = ledger_path(&cfg);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let records = parse_records(&text);
            Json(json!({
                "path": path.display().to_string(),
                "count": records.len(),
                "records": records,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!(
                "找不到證據日誌 {}（{e}）。請先執行：python -m examples.mock_demo",
                path.display()
            )})),
        )
            .into_response(),
    }
}

/// GET /api/verify — delegates the hash-chain check to `auditrail verify`.
async fn verify(State(cfg): State<Arc<Config>>) -> axum::response::Response {
    let path = ledger_path(&cfg);
    match Command::new(&cfg.auditrail_bin).arg("verify").arg(&path).output() {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if !err.is_empty() {
                text.push('\n');
                text.push_str(&err);
            }
            Json(json!({"ok": out.status.success(), "output": text})).into_response()
        }
        Err(e) => bin_missing(&cfg, e),
    }
}

/// GET /api/policy — the policy file as structured data, plus `auditrail lint` result.
async fn policy(State(cfg): State<Arc<Config>>) -> axum::response::Response {
    let path = policy_path(&cfg);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("找不到政策檔 {}（{e}）", path.display())})),
            )
                .into_response()
        }
    };
    let parsed: Value = match serde_yaml::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": format!("政策檔 YAML 格式錯誤：{e}")})),
            )
                .into_response()
        }
    };
    match Command::new(&cfg.auditrail_bin).arg("lint").arg(&path).output() {
        Ok(out) => Json(json!({
            "path": path.display().to_string(),
            "policy": parsed,
            "lint_ok": out.status.success(),
            "lint_output": String::from_utf8_lossy(&out.stdout).trim().to_string(),
        }))
        .into_response(),
        Err(e) => bin_missing(&cfg, e),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_records;

    #[test]
    fn parses_valid_lines_and_skips_blank_and_malformed() {
        let text = "{\"seq\":0,\"decision\":\"allow\"}\n\n   \nnot json\n{\"seq\":1,\"decision\":\"deny\"}\n";
        let records = parse_records(text);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["decision"], "deny");
    }

    #[test]
    fn empty_input_yields_no_records() {
        assert!(parse_records("").is_empty());
    }

    #[test]
    fn keeps_error_decisions_so_failures_are_visible() {
        let records = parse_records("{\"seq\":3,\"decision\":\"error\",\"reason\":\"TimeoutError\"}\n");
        assert_eq!(records[0]["decision"], "error");
    }
}
