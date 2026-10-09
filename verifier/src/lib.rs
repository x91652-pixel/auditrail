//! Independent verifier for auditrail evidence format v2 (docs/spec/evidence-format-v2.md).
//!
//! Written from the specification, not from the Python code: it shares nothing
//! with the `auditrail` package. Two implementations that agree on the
//! conformance vectors and on fuzzed input are what makes the format a format
//! rather than a library detail.
//!
//! File reading is deliberately strict (spec section 2): UTF-8 only, lines split on
//! `\n` only, no floats / `-0` / integers outside i64 / lone surrogates / nesting
//! deeper than 64, real calendar timestamps, lowercase hex. An odd input one
//! reader accepts and the other rejects is a way to smuggle a forgery past the weaker one.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TAG_RECORD: &[u8] = b"auditrail/record/v2\n";
const TAG_ANCHOR: &[u8] = b"auditrail/anchor/v2\n";
const MAX_DEPTH: usize = 64;

#[derive(Debug, Default)]
pub struct Options {
    /// {key_id: raw 32-byte public key}. `Some` means signatures are REQUIRED.
    pub public_keys: Option<HashMap<String, [u8; 32]>>,
    /// Anchor lines held by a witness (file bytes), checked without trusting the owner's anchors file.
    pub witness: Option<Vec<u8>>,
    /// The owner's anchors.jsonl bytes.
    pub anchors: Option<Vec<u8>>,
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

/// True when the value holds anything the format forbids: a float (including `-0`), an
/// integer outside i64, or nesting deeper than MAX_DEPTH.
fn unacceptable(v: &Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return true;
    }
    match v {
        Value::Number(n) => !n.is_i64(),
        Value::Array(a) => a.iter().any(|x| unacceptable(x, depth + 1)),
        Value::Object(o) => o.values().any(|x| unacceptable(x, depth + 1)),
        _ => false,
    }
}

fn record_hash(prev: &str, rec: &Map<String, Value>) -> String {
    let mut body = rec.clone();
    body.remove("hash");
    body.remove("sig");
    sha256_hex(format!("{}{}", prev, canonical(&Value::Object(body))).as_bytes())
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check_sig(pub_raw: &[u8; 32], tag: &[u8], message: &str, sig_hex: &str) -> bool {
    // exactly 128 lowercase hex characters: no whitespace, no capitals
    if !is_lower_hex(sig_hex, 128) {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(pub_raw) else { return false };
    let Ok(sig_bytes) = hex::decode(sig_hex) else { return false };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else { return false };
    let mut msg = tag.to_vec();
    msg.extend_from_slice(message.as_bytes());
    vk.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

/// Non-blank lines with their 1-based numbers: split on '\n' only, a trailing '\r' ignored,
/// lines of only spaces/tabs/'\r' skipped.
fn nonblank_lines(text: &str) -> Vec<(usize, &str)> {
    text.split('\n')
        .enumerate()
        .map(|(i, l)| (i + 1, l.strip_suffix('\r').unwrap_or(l)))
        .filter(|(_, l)| !l.trim_matches(|c| c == ' ' || c == '\t' || c == '\r').is_empty())
        .collect()
}

fn parse_object(line: &str) -> Result<Map<String, Value>, String> {
    match serde_json::from_str::<Value>(line) {
        Ok(Value::Object(m)) => {
            if unacceptable(&Value::Object(m.clone()), 1) {
                Err("contains a float, an integer outside 64 bits, or nesting deeper than 64".into())
            } else {
                Ok(m)
            }
        }
        Ok(_) => Err("line is not a JSON object".into()),
        Err(e) => Err(format!("not valid JSON: {e}")),
    }
}

/// Parse a whole ledger. On failure returns the records parsed so far and the problem.
fn parse_ledger(bytes: &[u8]) -> Result<Vec<Map<String, Value>>, Report> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(Report::fail("TAMPERED_LEDGER", "ledger file is not valid UTF-8".into(), None));
    };
    let mut records = Vec::new();
    for (lineno, line) in nonblank_lines(text) {
        match parse_object(line) {
            Ok(m) => records.push(m),
            Err(e) => {
                let i = records.len() as i64;
                return Err(Report::fail("TAMPERED_LEDGER", format!("record #{i} (line {lineno}): {e}"), Some(i)));
            }
        }
    }
    Ok(records)
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

/// Epoch seconds for `YYYY-MM-DDTHH:MM:SSZ` with real calendar values, years 1970-9999; else None.
pub fn epoch_of(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> {
        if b[a..z].iter().all(u8::is_ascii_digit) { ts[a..z].parse().ok() } else { None }
    };
    let (y, mo, d, h, mi, sec) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if leap { 29 } else { 28 },
        _ => return None,
    };
    if !(1970..=9999).contains(&y) || d < 1 || d > dim || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec)
}

fn is_int(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.is_i64())
}

/// Field rules of spec section 3, applied after a record's hash and signature hold.
fn check_fields(rec: &Map<String, Value>) -> Option<&'static str> {
    if s(rec, "ts").and_then(epoch_of).is_none() {
        return Some("ts is not a valid UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)");
    }
    let kind = rec.get("kind");
    if let Some(k) = kind {
        if !k.is_string() {
            return Some("kind is not a string");
        }
    }
    if kind.and_then(Value::as_str) == Some("heartbeat") {
        let ok_tools = matches!(rec.get("tools"), Some(Value::Array(a)) if a.iter().all(Value::is_string));
        if !ok_tools {
            return Some("heartbeat tools is not a list of strings");
        }
        if !is_int(rec.get("calls_attempted")) || !is_int(rec.get("calls_recorded")) {
            return Some("heartbeat call counts are not integers");
        }
    }
    None
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
    let version = match rec.get("anchor_version") {
        Some(Value::Number(n)) => n.as_i64(),
        _ => None,
    };
    let body_keys = version.and_then(anchor_body_keys).ok_or_else(|| tam("unsupported anchor_version"))?;
    let version = version.unwrap();
    if body_keys.iter().any(|k| !rec.contains_key(*k)) {
        return Err(tam("malformed anchor line"));
    }
    let allowed = |k: &String| {
        body_keys.contains(&k.as_str()) || matches!(k.as_str(), "anchor_hash" | "sink_ref") || (version == 2 && k == "sig")
    };
    if rec.keys().any(|k| !allowed(k)) {
        return Err(tam("unexpected fields in anchor line"));
    }
    if !matches!(rec.get("seq"), Some(Value::Number(n)) if n.as_i64().map_or(false, |v| v >= 0)) {
        return Err(tam("malformed anchor line"));
    }
    if body_keys.iter().filter(|k| !matches!(**k, "anchor_version" | "seq")).any(|k| !rec[*k].is_string()) {
        return Err(tam("malformed anchor line"));
    }
    if matches!(rec.get("sink_ref"), Some(v) if !v.is_string()) {
        return Err(tam("malformed anchor line"));
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

fn seq_of(rec: &Map<String, Value>) -> i64 {
    rec.get("seq").and_then(Value::as_i64).unwrap_or(-1)
}

/// Compare one valid anchor against the ledger. Err(report) on TRUNCATED / REWRITTEN.
fn compare_to_ledger(a: &Map<String, Value>, ledger: &[Map<String, Value>], what: &str) -> Result<i64, Report> {
    let seq = seq_of(a);
    let max_seq = ledger.last().map(seq_of).unwrap_or(-1);
    let Some(led) = ledger.iter().find(|r| seq_of(r) == seq) else {
        return Err(Report::fail("TRUNCATED", format!("ledger ends at seq={max_seq}, but {what} needs seq={seq}"), None));
    };
    if s(led, "hash") != s(a, "head_hash") {
        return Err(Report::fail("REWRITTEN", format!("record at anchored seq={seq} no longer matches the anchor's head_hash"), Some(seq)));
    }
    Ok(seq)
}

/// Read anchor lines strictly: Ok(lines) or (lines read before the problem, problem text).
fn anchor_lines(bytes: &[u8]) -> (Vec<Map<String, Value>>, Option<String>) {
    let Ok(text) = std::str::from_utf8(bytes) else { return (vec![], Some("anchor file is not valid UTF-8".into())) };
    let mut out = Vec::new();
    for (lineno, line) in nonblank_lines(text) {
        match parse_object(line) {
            Ok(m) => out.push(m),
            Err(_) => return (out, Some(format!("line {lineno}: malformed anchor line"))),
        }
    }
    (out, None)
}

/// The owner's anchors file: every line valid and chained first (spec check 3), then compared to the ledger.
fn check_anchors_file(bytes: &[u8], ledger: &[Map<String, Value>], keys: &Option<HashMap<String, [u8; 32]>>) -> Result<Option<i64>, Report> {
    let (lines, problem) = anchor_lines(bytes);
    let mut prev = GENESIS.to_string();
    for (i, a) in lines.iter().enumerate() {
        check_anchor_line(a, keys).map_err(|(st, d)| Report::fail(&st, format!("anchors file: line {}: {d}", i + 1), None))?;
        if s(a, "prev_anchor") != Some(prev.as_str()) {
            return Err(Report::fail("TAMPERED_ANCHOR", format!("anchors file: line {}: prev_anchor does not link to the previous anchor", i + 1), None));
        }
        prev = s(a, "anchor_hash").unwrap_or("").to_string();
    }
    if let Some(p) = problem {
        return Err(Report::fail("TAMPERED_ANCHOR", format!("anchors file: {p}"), None));
    }
    let mut upto = None;
    for a in &lines {
        let seq = compare_to_ledger(a, ledger, "anchors file")?;
        upto = Some(upto.map_or(seq, |u: i64| u.max(seq)));
    }
    Ok(upto)
}

/// A witness's copy: each line is validated and compared to the ledger in turn.
fn check_witness(bytes: &[u8], ledger: &[Map<String, Value>], keys: &Option<HashMap<String, [u8; 32]>>) -> Result<Option<i64>, Report> {
    let (lines, problem) = anchor_lines(bytes);
    let mut upto = None;
    for (i, a) in lines.iter().enumerate() {
        check_anchor_line(a, keys).map_err(|(st, d)| Report::fail(&st, format!("witness: line {}: {d}", i + 1), None))?;
        let seq = compare_to_ledger(a, ledger, "witness")?;
        upto = Some(upto.map_or(seq, |u: i64| u.max(seq)));
    }
    if let Some(p) = problem {
        return Err(Report::fail("TAMPERED_ANCHOR", format!("witness: {p}"), None));
    }
    Ok(upto)
}

pub fn verify(ledger_text: &str, opts: &Options) -> Report {
    verify_bytes(ledger_text.as_bytes(), opts)
}

pub fn verify_bytes(ledger_bytes: &[u8], opts: &Options) -> Report {
    let records = match parse_ledger(ledger_bytes) {
        Ok(r) => r,
        Err(rep) => return rep,
    };

    // 1 + 2: chain, signatures, field rules, record by record
    let mut prev = GENESIS.to_string();
    for (i, rec) in records.iter().enumerate() {
        let bad = |st: &str, d: String| Report::fail(st, d, Some(i as i64));
        if !matches!(rec.get("seq"), Some(Value::Number(n)) if n.as_i64() == Some(i as i64)) {
            return bad("TAMPERED_LEDGER", format!("expected seq={i}, found {:?}", rec.get("seq")));
        }
        if s(rec, "prev_hash") != Some(prev.as_str()) {
            return bad("TAMPERED_LEDGER", format!("seq={i}: prev_hash does not link to the previous record"));
        }
        let stored = s(rec, "hash").unwrap_or("").to_string();
        if s(rec, "hash").is_none() || record_hash(&prev, rec) != stored {
            return bad("TAMPERED_LEDGER", format!("seq={i}: hash does not match the record's contents"));
        }
        if let Some(keys) = &opts.public_keys {
            let key_id = s(rec, "key_id").filter(|k| !k.is_empty());
            let sig = s(rec, "sig").filter(|k| !k.is_empty());
            let (Some(key_id), Some(sig)) = (key_id, sig) else {
                return bad("UNSIGNED_RECORD", format!("seq={i} carries no signature, but signatures are required"));
            };
            let Some(p) = keys.get(key_id) else {
                return bad("UNKNOWN_KEY", format!("seq={i} is signed by key_id={key_id}, which is not in the trusted keys"));
            };
            if !check_sig(p, TAG_RECORD, &stored, sig) {
                return bad("BAD_SIGNATURE", format!("seq={i}: signature does not verify"));
            }
        }
        if let Some(why) = check_fields(rec) {
            return bad("MALFORMED_RECORD", format!("seq={i}: {why}"));
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

    // 3: the owner's anchors file, 4: the witness's copy
    if let Some(bytes) = &opts.anchors {
        match check_anchors_file(bytes, &records, &opts.public_keys) {
            Ok(u) => fold(u),
            Err(mut r) => {
                r.records = n;
                return r;
            }
        }
    }
    if let Some(bytes) = &opts.witness {
        match check_witness(bytes, &records, &opts.public_keys) {
            Ok(u) => fold(u),
            Err(mut r) => {
                r.records = n;
                return r;
            }
        }
    }

    // 5: heartbeats (field types were already checked above)
    if let Some(max_gap) = opts.max_gap_s {
        let beats: Vec<&Map<String, Value>> = records.iter().filter(|r| s(r, "kind") == Some("heartbeat")).collect();
        if beats.is_empty() && n > 0 {
            let mut r = Report::fail("NO_HEARTBEAT", "a maximum gap was given but the ledger has no heartbeat records".into(), None);
            r.records = n;
            return r;
        }
        let ts = |m: &Map<String, Value>| s(m, "ts").and_then(epoch_of).unwrap_or(0);
        let mut points: Vec<i64> = Vec::new();
        if let Some(r) = records.first() {
            points.push(ts(r));
        }
        points.extend(beats.iter().map(|b| ts(b)));
        if let Some(r) = records.last() {
            points.push(ts(r));
        }
        for b in &beats {
            if b.get("calls_attempted") != b.get("calls_recorded") {
                let seq = seq_of(b);
                let mut r = Report::fail(
                    "UNRECORDED_CALLS",
                    format!("heartbeat seq={seq}: calls were intercepted but not all recorded"),
                    Some(seq),
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
