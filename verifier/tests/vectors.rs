//! Runs every conformance vector in docs/spec/vectors through the Rust verifier.
//! The Python verifier runs the same vectors (tests/test_vectors.py); both must agree with expected.json.

use auditrail_verify::{key_id_for, parse_pubkey_hex, verify, Options};
use serde_json::Value;
use std::{collections::HashMap, fs, path::PathBuf};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("docs").join("spec").join("vectors")
}

#[test]
fn every_vector_matches_its_expected_result() {
    let mut cases: Vec<PathBuf> = fs::read_dir(vectors_dir())
        .expect("vectors dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    cases.sort();
    assert!(cases.len() >= 10, "expected at least 10 vectors, found {}", cases.len());

    let mut failures = Vec::new();
    for case in &cases {
        let exp: Value = serde_json::from_str(&fs::read_to_string(case.join("expected.json")).unwrap()).unwrap();
        let args = &exp["args"];
        let mut opts = Options::default();
        if args["require_signatures"].as_bool() == Some(true) {
            let raw = parse_pubkey_hex(&fs::read_to_string(case.join("recorder.pub")).unwrap()).unwrap();
            opts.public_keys = Some(HashMap::from([(key_id_for(&raw), raw)]));
        }
        if let Some(w) = args["witness"].as_str() {
            opts.witness = Some(fs::read_to_string(case.join(w)).unwrap());
        }
        opts.max_gap_s = args["max_gap_s"].as_i64();

        let got = verify(&fs::read_to_string(case.join("ledger.jsonl")).unwrap(), &opts);
        let name = case.file_name().unwrap().to_string_lossy().to_string();
        let mut problems = Vec::new();
        if got.status != exp["status"].as_str().unwrap() {
            problems.push(format!("status: expected {}, got {} ({})", exp["status"], got.status, got.detail));
        }
        for (key, value) in [("bad_seq", got.bad_seq), ("anchored_upto", got.anchored_upto), ("unanchored_tail", got.unanchored_tail)] {
            if let Some(want) = exp.get(key) {
                if *want != serde_json::json!(value) {
                    problems.push(format!("{key}: expected {want}, got {value:?}"));
                }
            }
        }
        if !problems.is_empty() {
            failures.push(format!("{name}: {}", problems.join("; ")));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn a_float_in_a_record_is_rejected_because_other_languages_could_not_reproduce_its_hash() {
    let line = r#"{"format":2,"seq":0,"ts":"2026-01-01T00:00:00Z","kind":"heartbeat","x":1.5,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"00"}"#;
    let r = verify(line, &Options::default());
    assert_eq!(r.status, "TAMPERED_LEDGER");
}
