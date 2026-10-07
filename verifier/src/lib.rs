//! Independent verifier for auditrail evidence format v2 (docs/spec/evidence-format-v2.md).
//!
//! Written from the specification, not from the Python code: it shares nothing
//! with the `auditrail` package. Two implementations that agree on the
//! conformance vectors are what makes the format a format rather than a library detail.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TAG_RECORD: &[u8] = b"auditrail/record/v2\n";
const TAG_ANCHOR: &[u8] = b"auditrail/anchor/v2\n";

#[derive(Debug, Default)]
pub struct Options {
    /// {key_id: raw 32-byte public key}. `Some` means signatures are REQUIRED.
    pub public_keys: Option<HashMap<String, [u8; 32]>>,
    /// Anchor lines held by a witness (JSONL text), checked without trusting the owner's anchors file.
    pub witness: Option<String>,
    /// The owner's anchors.jsonl text.
    pub anchors: Option<String>,
    pub max_gap_s: Option<i64>,
}

#[derive(Debug)]
pub struct Report {
    pub status: String,
    pub detail: String,
    pub bad_seq: Option<i64>,
    pub records: usize,
    pub anchored_upto: Option<i64>,
    pub unanchored_tail: Option<i64>,
}

impl Report {
    fn fail(status: &str, detail: String, bad_seq: Option<i64>) -> Report {
        Report { status: status.into(), detail, bad_seq, records: 0, anchored_upto: None, unanchored_tail: None }
    }
    pub fn ok(&self) -> bool {
        self.status == "OK"
    }
    pub fn to_json(&self) -> Value {
        json!({
            "status": self.status, "detail": self.detail, "bad_seq": self.bad_seq, "records": self.records,
            "anchored_upto": self.anchored_upto, "unanchored_tail": self.unanchored_tail,
        })
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// key_id = first 16 hex chars of sha256(raw public key).
pub fn key_id_for(raw: &[u8; 32]) -> String {
    sha256_hex(raw)[..16].to_string()
}

pub fn parse_pubkey_hex(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim()).map_err(|e| format!("bad public key hex: {e}"))?;
    bytes.try_into().map_err(|_| "public key must be 32 bytes".to_string())
}

/// Canonical JSON: keys sorted by code point, no whitespace, non-ASCII left as UTF-8.
/// serde_json (without `preserve_order`) stores objects in a BTreeMap, which sorts
/// by UTF-8 bytes, the same order as code points.
fn canonical(v: &Value) -> String {
    serde_json::to_string(v).expect("a Value always serializes")
}

fn has_float(v: &Value) -> bool {
    match v {
        Value::Number(n) => !(n.is_i64() || n.is_u64()),
        Value::Array(a) => a.iter().any(has_float),
        Value::Object(o) => o.values().any(has_float),
        _ => false,
    }
}

fn record_hash(prev: &str, rec: &Map<String, Value>) -> String {
    let mut body = rec.clone();
    body.remove("hash");
    body.remove("sig");
    sha256_hex(format!("{}{}", prev, canonical(&Value::Object(body))).as_bytes())
}

fn check_sig(pub_raw: &[u8; 32], tag: &[u8], message: &str, sig_hex: &str) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pub_raw) else { return false };
    let Ok(sig_bytes) = hex::decode(sig_hex) else { return false };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else { return false };
    let mut msg = tag.to_vec();
    msg.extend_from_slice(message.as_bytes());
    vk.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

fn parse_lines(text: &str) -> Result<Vec<Map<String, Value>>, (usize, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(m)) => out.push(m),
            Ok(_) => return Err((i, "line is not a JSON object".into())),
            Err(e) => return Err((i, format!("not valid JSON: {e}"))),
        }
    }
    Ok(out)
}

fn s<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn epoch_of(ts: &str) -> Option<i64> {
    // YYYY-MM-DDTHH:MM:SSZ
    let b = ts.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |a: usize, z: usize| ts[a..z].parse::<i64>().ok();
    Some(days_from_civil(n(0, 4)?, n(5, 7)?, n(8, 10)?) * 86400 + n(11, 13)? * 3600 + n(14, 16)? * 60 + n(17, 19)?)
}

fn anchor_body_keys(version: i64) -> Option<&'static [&'static str]> {
    match version {
        1 => Some(&["anchor_version", "seq", "head_hash", "prev_anchor", "created_at"]),
        2 => Some(&["anchor_version", "seq", "head_hash", "prev_anchor", "created_at", "key_id"]),
        _ => None,
    }
}

/// Validate one anchor line on its own. Returns (status, detail) on failure.
fn check_anchor_line(rec: &Map<String, Value>, keys: &Option<HashMap<String, [u8; 32]>>) -> Result<(), (String, String)> {
    let tam = |d: &str| ("TAMPERED_ANCHOR".to_string(), d.to_string());
    let version = rec.get("anchor_version").and_then(Value::as_i64).ok_or_else(|| tam("unsupported anchor_version"))?;
    let body_keys = anchor_body_keys(version).ok_or_else(|| tam("unsupported anchor_version"))?;
    if body_keys.iter().any(|k| !rec.contains_key(*k)) {
        return Err(tam("malformed anchor line"));
    }
    let allowed = |k: &String| body_keys.contains(&k.as_str()) || matches!(k.as_str(), "anchor_hash" | "sink_ref" | "sig");
    if rec.keys().any(|k| !allowed(k)) || (version == 1 && rec.contains_key("sig")) {
        return Err(tam("unexpected fields in anchor line"));
    }
    let mut body = Map::new();
    for k in body_keys {
        body.insert((*k).to_string(), rec[*k].clone());
    }
    let anchor_hash = sha256_hex(canonical(&Value::Object(body)).as_bytes());
    if s(rec, "anchor_hash") != Some(anchor_hash.as_str()) {
        return Err(tam("anchor_hash does not match body"));
    }
    if version == 2 {
        let key_id = s(rec, "key_id").unwrap_or("");
        if let Some(map) = keys {
            match map.get(key_id) {
                None => return Err(("UNKNOWN_KEY".into(), format!("anchor is signed by key_id={key_id}, which is not in the trusted keys"))),
                Some(p) => {
                    if !check_sig(p, TAG_ANCHOR, &anchor_hash, s(rec, "sig").unwrap_or("")) {
                        return Err(("BAD_SIGNATURE".into(), "anchor signature does not verify".into()));
                    }
                }
            }
        }
    } else if keys.is_some() {
        return Err(("UNSIGNED_ANCHOR".into(), "anchor is unsigned (version 1), but signatures are required".into()));
    }
    Ok(())
}

/// Check anchors against the ledger. Returns Ok(Some(highest anchored seq)) or the failing report.
fn check_anchors(
    text: &str,
    ledger: &[Map<String, Value>],
    keys: &Option<HashMap<String, [u8; 32]>>,
    chain_links: bool,
    what: &str,
) -> Result<Option<i64>, Report> {
    let lines = parse_lines(text).map_err(|(i, e)| Report::fail("TAMPERED_ANCHOR", format!("{what}: line {}: {e}", i + 1), None))?;
    let mut prev = GENESIS.to_string();
    let mut upto: Option<i64> = None;
    let max_seq = ledger.last().and_then(|r| r.get("seq")).and_then(Value::as_i64);
    for (i, a) in lines.iter().enumerate() {
        check_anchor_line(a, keys).map_err(|(st, d)| Report::fail(&st, format!("{what}: line {}: {d}", i + 1), None))?;
        if chain_links {
            if s(a, "prev_anchor") != Some(prev.as_str()) {
                return Err(Report::fail("TAMPERED_ANCHOR", format!("{what}: line {}: prev_anchor does not link to the previous anchor", i + 1), None));
            }
            prev = s(a, "anchor_hash").unwrap_or("").to_string();
        }
        let seq = a.get("seq").and_then(Value::as_i64).unwrap_or(-1);
        let Some(led) = ledger.iter().find(|r| r.get("seq").and_then(Value::as_i64) == Some(seq)) else {
            return Err(Report::fail(
                "TRUNCATED",
                format!("ledger ends at seq={}, but {what} needs seq={seq}", max_seq.unwrap_or(-1)),
                None,
            ));
        };
        if s(led, "hash") != s(a, "head_hash") {
            return Err(Report::fail(
                "REWRITTEN",
                format!("record at anchored seq={seq} no longer matches the anchor's head_hash"),
                Some(seq),
            ));
        }
        upto = Some(upto.map_or(seq, |u| u.max(seq)));
    }
    Ok(upto)
}

pub fn verify(ledger_text: &str, opts: &Options) -> Report {
    let records = match parse_lines(ledger_text) {
        Ok(r) => r,
        Err((i, e)) => return Report::fail("TAMPERED_LEDGER", format!("record #{i}: {e}"), Some(i as i64)),
    };

    // 1 + 2: chain and signatures
    let mut prev = GENESIS.to_string();
    for (i, rec) in records.iter().enumerate() {
        let bad = |st: &str, d: String| Report::fail(st, d, Some(i as i64));
        if rec.get("seq").and_then(Value::as_i64) != Some(i as i64) {
            return bad("TAMPERED_LEDGER", format!("expected seq={i}, found {:?}", rec.get("seq")));
        }
        if has_float(&Value::Object(rec.clone())) {
            return bad("TAMPERED_LEDGER", format!("seq={i}: record contains a float"));
        }
        if s(rec, "prev_hash") != Some(prev.as_str()) {
            return bad("TAMPERED_LEDGER", format!("seq={i}: prev_hash does not link to the previous record"));
        }
        let stored = s(rec, "hash").unwrap_or("").to_string();
        if record_hash(&prev, rec) != stored {
            return bad("TAMPERED_LEDGER", format!("seq={i}: hash does not match the record's contents"));
        }
        if let Some(keys) = &opts.public_keys {
            let (Some(key_id), Some(sig)) = (s(rec, "key_id"), s(rec, "sig")) else {
                return bad("UNSIGNED_RECORD", format!("seq={i} carries no signature, but signatures are required"));
            };
            let Some(p) = keys.get(key_id) else {
                return bad("UNKNOWN_KEY", format!("seq={i} is signed by key_id={key_id}, which is not in the trusted keys"));
            };
            if !check_sig(p, TAG_RECORD, &stored, sig) {
                return bad("BAD_SIGNATURE", format!("seq={i}: signature does not verify"));
            }
        }
        prev = stored;
    }

    let n = records.len();
    let mut upto: Option<i64> = None;
    let mut fold = |u: Option<i64>| {
        if let Some(u) = u {
            upto = Some(upto.map_or(u, |c| c.max(u)));
        }
    };

    // 3: the owner's anchors file
    if let Some(text) = &opts.anchors {
        match check_anchors(text, &records, &opts.public_keys, true, "anchors file") {
            Ok(u) => fold(u),
            Err(mut r) => {
                r.records = n;
                return r;
            }
        }
    }
    // 4: the witness's copy
    if let Some(text) = &opts.witness {
        match check_anchors(text, &records, &opts.public_keys, false, "witness") {
            Ok(u) => fold(u),
            Err(mut r) => {
                r.records = n;
                return r;
            }
        }
    }

    // 5: heartbeats
    if let Some(max_gap) = opts.max_gap_s {
        let beats: Vec<&Map<String, Value>> = records.iter().filter(|r| s(r, "kind") == Some("heartbeat")).collect();
        if beats.is_empty() && n > 0 {
            let mut r = Report::fail("NO_HEARTBEAT", "a maximum gap was given but the ledger has no heartbeat records".into(), None);
            r.records = n;
            return r;
        }
        let ts = |m: &Map<String, Value>| s(m, "ts").and_then(epoch_of);
        let mut points: Vec<i64> = Vec::new();
        if let Some(t) = records.first().and_then(|r| ts(r)) {
            points.push(t);
        }
        points.extend(beats.iter().filter_map(|b| ts(b)));
        if let Some(t) = records.last().and_then(|r| ts(r)) {
            points.push(t);
        }
        for b in &beats {
            if b.get("calls_attempted") != b.get("calls_recorded") {
                let seq = b.get("seq").and_then(Value::as_i64);
                let mut r = Report::fail(
                    "UNRECORDED_CALLS",
                    format!("heartbeat seq={}: calls were intercepted but not all recorded", seq.unwrap_or(-1)),
                    seq,
                );
                r.records = n;
                return r;
            }
        }
        let gaps: Vec<i64> = points.windows(2).map(|w| w[1] - w[0]).filter(|g| *g > max_gap).collect();
        if !gaps.is_empty() {
            let mut r = Report::fail("HEARTBEAT_GAP", format!("{} period(s) longer than {max_gap}s with no heartbeat", gaps.len()), None);
            r.records = n;
            return r;
        }
    }

    let tail = match upto {
        Some(u) => n as i64 - (u + 1),
        None => n as i64,
    };
    Report {
        status: "OK".into(),
        detail: format!("{n} record(s), chain intact"),
        bad_seq: None,
        records: n,
        anchored_upto: upto,
        unanchored_tail: Some(tail),
    }
}
