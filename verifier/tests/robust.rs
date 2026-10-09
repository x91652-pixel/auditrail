//! The verifier reads untrusted files, so it must answer every input with a status and never panic.
//! This mutates every conformance vector thousands of ways (flip, insert, delete, duplicate, swap, cut)
//! and runs all check combinations. A panic anywhere fails the test.
//! Deterministic: a fixed-seed xorshift generator, so a failure reproduces.

use auditrail_verify::{key_id_for, parse_pubkey_hex, verify_bytes, Options};
use std::{collections::HashMap, fs, path::PathBuf};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

fn vectors() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("docs").join("spec").join("vectors");
    let mut v: Vec<PathBuf> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect();
    v.sort();
    v
}

fn mutate(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut d = data.to_vec();
    for _ in 0..=rng.below(4) {
        if d.is_empty() {
            d.push(b'{');
        }
        match rng.below(7) {
            0 => {
                let i = rng.below(d.len());
                d[i] = rng.next() as u8;
            }
            1 => {
                let i = rng.below(d.len() + 1);
                d.insert(i, rng.next() as u8);
            }
            2 => {
                let i = rng.below(d.len());
                d.remove(i);
            }
            3 => {
                let i = rng.below(d.len());
                let j = (i + rng.below(40)).min(d.len());
                let chunk = d[i..j].to_vec();
                let at = rng.below(d.len() + 1);
                for (k, b) in chunk.iter().enumerate() {
                    d.insert(at + k, *b);
                }
            }
            4 => {
                let keep = rng.below(d.len() + 1);
                d.truncate(keep);
            }
            5 => {
                let i = rng.below(d.len());
                let j = rng.below(d.len());
                d.swap(i, j);
            }
            _ => {
                let pieces: [&[u8]; 8] = [b"\"", b"\\u", b"-0", b"1e999", b"[[[[[[[[", b"\\ud800", b"\xff\xfe", b"\r\n"];
                let i = rng.below(d.len() + 1);
                for (k, b) in pieces[rng.below(pieces.len())].iter().enumerate() {
                    d.insert((i + k).min(d.len()), *b);
                }
            }
        }
    }
    d
}

#[test]
fn no_input_makes_the_verifier_panic() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut runs = 0u64;
    let mut statuses: HashMap<String, u64> = HashMap::new();
    for case in vectors() {
        let ledger = fs::read(case.join("ledger.jsonl")).unwrap();
        let witness = fs::read(case.join("witness.jsonl")).ok();
        let anchors = fs::read(case.join("anchors.jsonl")).ok();
        let key = fs::read_to_string(case.join("recorder.pub")).ok().and_then(|t| parse_pubkey_hex(&t).ok());
        for i in 0..1500 {
            let mut opts = Options::default();
            if let Some(k) = key {
                if i % 3 != 0 {
                    opts.public_keys = Some(HashMap::from([(key_id_for(&k), k)]));
                }
            }
            if i % 2 == 0 {
                opts.max_gap_s = Some(rng.below(7200) as i64 - 10);
            }
            // sometimes corrupt the ledger, sometimes the witness/anchor files, sometimes all
            let l = if i % 4 != 3 { mutate(&mut rng, &ledger) } else { ledger.clone() };
            opts.witness = witness.as_ref().map(|w| if i % 5 == 1 { mutate(&mut rng, w) } else { w.clone() });
            opts.anchors = anchors.as_ref().map(|a| if i % 5 == 2 { mutate(&mut rng, a) } else { a.clone() });
            let rep = verify_bytes(&l, &opts);
            *statuses.entry(rep.status).or_insert(0) += 1;
            runs += 1;
        }
    }
    assert!(runs >= 15_000, "ran only {runs}");
    // the mutations must reach several different failure paths, or this test proves little
    assert!(statuses.len() >= 6, "only reached statuses: {statuses:?}");
}

#[test]
fn arbitrary_short_byte_strings_are_answered() {
    let mut rng = Rng(0xD1B54A32D192ED03);
    let alphabet: &[u8] = b"{}[]\":,0123456789abcdefnultrse\\ \n\r\t-+.E\xc3\xa9\xff";
    for _ in 0..30_000 {
        let n = rng.below(120);
        let bytes: Vec<u8> = (0..n).map(|_| alphabet[rng.below(alphabet.len())]).collect();
        let opts = Options { max_gap_s: Some(60), witness: Some(bytes.clone()), anchors: Some(bytes.clone()), ..Default::default() };
        let _ = verify_bytes(&bytes, &opts);
    }
}
