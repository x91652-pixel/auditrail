//! auditrail-verify: a single offline binary that checks an evidence ledger.
//!
//!   auditrail-verify LEDGER [--pubkey FILE]... [--anchors FILE] [--witness FILE] [--max-gap SECONDS] [--json]
//!
//! Exit code 0 only when every requested check passes; 1 when a check fails;
//! 2 when a file cannot be read at all. Anything it was not asked to check is
//! listed under "not checked", never silently treated as passed.

use auditrail_verify::{key_id_for, parse_pubkey_hex, verify_bytes, Options};
use std::{collections::HashMap, fs, process::ExitCode};

fn usage() -> ExitCode {
    eprintln!("usage: auditrail-verify LEDGER [--pubkey FILE]... [--anchors FILE] [--witness FILE] [--max-gap SECONDS] [--json]");
    ExitCode::from(2)
}

fn read(path: &str) -> Result<Vec<u8>, ExitCode> {
    fs::read(path).map_err(|e| {
        eprintln!("[ERROR] {path}: {e}");
        ExitCode::from(2)
    })
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(ledger_path) = args.next() else { return usage() };
    if ledger_path.starts_with("--") {
        return usage();
    }
    let mut opts = Options::default();
    let mut keys: HashMap<String, [u8; 32]> = HashMap::new();
    let mut json = false;
    while let Some(flag) = args.next() {
        let mut value = || args.next();
        match flag.as_str() {
            "--json" => json = true,
            "--pubkey" => {
                let Some(p) = value() else { return usage() };
                let bytes = match read(&p) {
                    Ok(t) => t,
                    Err(c) => return c,
                };
                match parse_pubkey_hex(&String::from_utf8_lossy(&bytes)) {
                    Ok(raw) => {
                        keys.insert(key_id_for(&raw), raw);
                    }
                    Err(e) => {
                        eprintln!("[ERROR] {p}: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--anchors" | "--witness" => {
                let Some(p) = value() else { return usage() };
                let bytes = match read(&p) {
                    Ok(t) => t,
                    Err(c) => return c,
                };
                if flag == "--anchors" {
                    opts.anchors = Some(bytes);
                } else {
                    opts.witness = Some(bytes);
                }
            }
            "--max-gap" => match value().and_then(|v| v.parse::<i64>().ok()) {
                Some(n) => opts.max_gap_s = Some(n),
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    if !keys.is_empty() {
        opts.public_keys = Some(keys);
    }
    let ledger = match read(&ledger_path) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let report = verify_bytes(&ledger, &opts);

    let mut not_checked = Vec::new();
    if opts.public_keys.is_none() {
        not_checked.push("signatures (no --pubkey: anyone with write access could have rewritten the chain)");
    }
    if opts.anchors.is_none() && opts.witness.is_none() {
        not_checked.push("anchors/witness (truncation and whole-chain rewrites are not detectable)");
    }
    if opts.max_gap_s.is_none() {
        not_checked.push("heartbeats (no --max-gap: silent periods are not detectable)");
    }

    if json {
        let mut v = report.to_json();
        v["not_checked"] = serde_json::json!(not_checked);
        println!("{v}");
    } else if report.ok() {
        println!("[OK] {ledger_path}: {}", report.detail);
        if let Some(u) = report.anchored_upto {
            println!("  anchored up to seq={u} ({} record(s) after it not covered)", report.unanchored_tail.unwrap_or(0));
        }
        for n in &not_checked {
            println!("  not checked: {n}");
        }
    } else {
        println!("[{}] {}", report.status, report.detail);
        if let Some(b) = report.bad_seq {
            println!("  bad_seq={b}");
        }
    }
    if report.ok() { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
