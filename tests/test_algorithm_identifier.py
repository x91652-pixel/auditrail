"""D-11: the optional `sig_alg` member, `anchor_version` 3 and `UNSUPPORTED_FORMAT`.

Rules under test (docs/design/d11-algorithm-and-format-identifiers.md, decisions D-12):
- absent `sig_alg` means ed25519 and is how ed25519 is written: default ledgers are byte-identical to before
- an explicit "ed25519", or anything outside the token grammar, is MALFORMED_RECORD (TAMPERED_ANCHOR for anchors)
- a well-formed token this verifier does not implement is UNSUPPORTED_ALGORITHM when keys are given -- never OK
- `format` an integer other than 2 is UNSUPPORTED_FORMAT; a missing `format` is still LEGACY_FORMAT
- a caller can never set `sig_alg` through the event/call fields
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from auditrail import Ledger, Signer
from auditrail import keys as keys_mod
from auditrail.anchor import FileSink, anchor_ledger
from auditrail.keys import TrustedKeys
from auditrail.ledger import GENESIS_HASH, InvalidRecord, _canonical, record_hash
from auditrail.verifier import verify_all

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")
SEED = bytes(range(32))


class FutureSigner(Signer):
    alg = "x-future-alg"


def make_ledger(path, signer, n=4):
    led = Ledger(path, signer=signer, fsync=False)
    for i in range(n):
        led.record(agent_id="a", session_id="s", policy_version="p", tool="t", categories=["internal"],
                   args={"i": i}, decision="allow", reason=None)
    return led


def rewrite(path, fn):
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    fn(recs)
    prev = GENESIS_HASH
    for r in recs:
        r["prev_hash"] = prev
        r["hash"] = record_hash(prev, r)
        prev = r["hash"]
    path.write_text("".join(_canonical(r) + "\n" for r in recs), encoding="utf-8", newline="\n")


def pub_file(tmp_path, signer):
    p = tmp_path / "k.pub"
    p.write_text(signer.public_hex + "\n", encoding="utf-8")
    return p


def rust(ledger, pub=None, witness=None):
    if BINARY is None:
        pytest.skip("Rust verifier not built; the Python half above passed, the Rust half did not run")
    cmd = [str(BINARY), str(ledger), "--json"]
    if pub:
        cmd += ["--pubkey", str(pub)]
    if witness:
        cmd += ["--witness", str(witness)]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return json.loads(out.stdout)


@pytest.fixture
def default_signer():
    return Signer.from_seed(SEED)


# ---------------------------------------------------------------- the default is unchanged

def test_a_default_ledger_never_contains_sig_alg_and_anchors_stay_version_2(tmp_path, default_signer):
    led = make_ledger(tmp_path / "l.jsonl", default_signer)
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(tmp_path / "w.jsonl"), signer=default_signer)
    assert "sig_alg" not in (tmp_path / "l.jsonl").read_text(encoding="utf-8")
    anchor = json.loads((tmp_path / "w.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert anchor["anchor_version"] == 2 and "sig_alg" not in anchor
    assert Signer.alg == "ed25519"


def test_a_default_ledger_verifies_exactly_as_before(tmp_path, default_signer):
    make_ledger(tmp_path / "l.jsonl", default_signer)
    res = verify_all(tmp_path / "l.jsonl", public_keys={default_signer.key_id: default_signer.public_hex})
    assert res["status"] == "OK" and res["unchecked_algorithms"] == []


# ---------------------------------------------------------------- a writer cannot forge the member

def test_record_event_and_the_ledger_refuse_sig_alg_as_an_ordinary_field(tmp_path, default_signer):
    led = Ledger(tmp_path / "l.jsonl", signer=default_signer, fsync=False)
    with pytest.raises(InvalidRecord, match=r"fields \['sig_alg'\] are set by the ledger itself"):
        led.record_event("heartbeat", sig_alg="x-future-alg", recorder_id="r", tools=[], policy_version="p",
                         policy_hash=None, calls_attempted=0, calls_recorded=0, interval_s=1)
    with pytest.raises(InvalidRecord, match="sig_alg"):
        led._append({"kind": "call", "sig_alg": "x-future-alg"})
    with pytest.raises(InvalidRecord):  # the exact-field-set path used by the recorder service
        led.append_call({"sig_alg": "x-future-alg"})
    assert not (tmp_path / "l.jsonl").exists() or "sig_alg" not in (tmp_path / "l.jsonl").read_text(encoding="utf-8")


def test_a_non_default_signer_writes_the_member_and_the_ledger_hashes_it(tmp_path):
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    recs = [json.loads(x) for x in (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(r["sig_alg"] == "x-future-alg" for r in recs)
    r = dict(recs[1])
    r.pop("hash")
    r.pop("sig")
    assert record_hash(recs[0]["hash"], r) == recs[1]["hash"], "sig_alg is inside the hashed body"
    edited = json.loads(json.dumps(recs))
    edited[1]["sig_alg"] = "x-other-alg"
    (tmp_path / "e.jsonl").write_text("".join(_canonical(x) + "\n" for x in edited), encoding="utf-8", newline="\n")
    res = verify_all(tmp_path / "e.jsonl")
    assert res["status"] == "TAMPERED_LEDGER" and res["bad_seq"] == 1, "swapping the algorithm breaks the hash"


# ---------------------------------------------------------------- unsupported algorithm: never a quiet OK


def test_a_record_naming_another_algorithm_under_an_ed25519_key_is_a_mismatch_in_both_languages(tmp_path):
    """D-14: every key read from a .pub file is an Ed25519 key, so a record claiming another algorithm is not a
    signature that key made -- BAD_SIGNATURE ("algorithm mismatch"), whether or not the algorithm is implemented.
    (This used to be UNSUPPORTED_ALGORITHM; that let anyone turn a forgery into 'could not judge'.)"""
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    pub = pub_file(tmp_path, s)
    res = verify_all(tmp_path / "l.jsonl", public_keys={s.key_id: s.public_hex})
    assert res["status"] == "BAD_SIGNATURE" and res["bad_seq"] == 0
    assert "algorithm mismatch" in res["detail"]
    r = rust(tmp_path / "l.jsonl", pub)
    assert r["status"] == "BAD_SIGNATURE" and r["bad_seq"] == 0 and "algorithm mismatch" in r["detail"]


def registered_as_future(s):
    """Trusted keys as the Python API can express them: the key is registered as an 'x-future-alg' key."""
    return TrustedKeys({s.key_id: s.public_hex}, {s.key_id: "x-future-alg"})


def test_unsupported_algorithm_is_reached_only_when_the_key_is_registered_as_that_type(tmp_path):
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    res = verify_all(tmp_path / "l.jsonl", public_keys=registered_as_future(s))
    assert res["status"] == "UNSUPPORTED_ALGORITHM" and res["bad_seq"] == 0
    assert "Inconclusive, not OK" in res["detail"] and "not evidence of tampering" not in res["detail"]
    assert "does not mean the records were not tampered with" in res["detail"]


def test_a_definite_finding_outranks_unsupported_even_when_the_key_is_registered_as_that_type(tmp_path):
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s, n=5)
    recs = [json.loads(x) for x in (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    recs[3]["decision"] = "deny"  # not re-hashed
    (tmp_path / "e.jsonl").write_text("".join(_canonical(x) + "\n" for x in recs), encoding="utf-8", newline="\n")
    res = verify_all(tmp_path / "e.jsonl", public_keys=registered_as_future(s))
    assert res["status"] == "TAMPERED_LEDGER" and res["bad_seq"] == 3


def test_unsupported_algorithm_without_keys_is_ok_with_a_note_in_both_languages(tmp_path):
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    res = verify_all(tmp_path / "l.jsonl")
    assert res["status"] == "OK" and res["unchecked_algorithms"] == ["x-future-alg"]
    assert any("cannot check" in n for n in res["notes"])
    r = rust(tmp_path / "l.jsonl")
    assert r["status"] == "OK" and r["unchecked_algorithms"] == ["x-future-alg"]



def test_only_one_verifier_supports_the_algorithm(tmp_path, monkeypatch):
    """Python is given an implementation of 'x-future-alg' and a key registered as that type; the Rust verifier can
    only be given Ed25519 keys, so for the same bytes it says BAD_SIGNATURE (mismatch) and never OK."""
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    pub = pub_file(tmp_path, s)
    monkeypatch.setitem(keys_mod._VERIFIERS, "x-future-alg", keys_mod.verify_sig)
    assert verify_all(tmp_path / "l.jsonl", public_keys=registered_as_future(s))["status"] == "OK"
    r = rust(tmp_path / "l.jsonl", pub)
    assert r["status"] == "BAD_SIGNATURE" and r["status"] != "OK"


def test_a_bad_signature_under_a_supported_extra_algorithm_is_still_caught(tmp_path, monkeypatch):
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    monkeypatch.setitem(keys_mod._VERIFIERS, "x-future-alg", keys_mod.verify_sig)
    other = FutureSigner.from_seed(bytes(range(32, 64)))
    trusted = TrustedKeys({s.key_id: other.public_hex}, {s.key_id: "x-future-alg"})  # right id, wrong key
    res = verify_all(tmp_path / "l.jsonl", public_keys=trusted)
    assert res["status"] == "BAD_SIGNATURE"


def test_algorithm_mismatch_between_record_and_trusted_key_is_a_bad_signature(tmp_path, monkeypatch):
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    monkeypatch.setitem(keys_mod._VERIFIERS, "x-future-alg", keys_mod.verify_sig)
    trusted = TrustedKeys({s.key_id: s.public_hex}, {s.key_id: "ed25519"})  # the trusted key is an ed25519 key
    res = verify_all(tmp_path / "l.jsonl", public_keys=trusted)
    assert res["status"] == "BAD_SIGNATURE" and "algorithm mismatch" in res["detail"]


# ---------------------------------------------------------------- the grammar, in both languages

BAD_TOKENS = ["ES256", "Ed25519", "ED25519", " es256", "es256 ", "es256\n", "es\n256", "es256\r", "es256\x00",
              "es_256", "es.256", "ｅｓ２５６", "es２56", "", "a" * 33, "é", None, 5, True, False, ["es256"],
              {"alg": "es256"}]  # (a float is rejected while parsing, in both languages: the no-floats rule)
GOOD_TOKENS = ["x-future-alg", "es256", "ml-dsa-65", "a", "0", "a" * 32, "-", "--"]


@pytest.mark.parametrize("value", BAD_TOKENS, ids=lambda v: repr(v))
def test_a_value_outside_the_grammar_is_malformed_in_both_languages(tmp_path, default_signer, value):
    make_ledger(tmp_path / "l.jsonl", default_signer)
    rewrite(tmp_path / "l.jsonl", lambda r: r[2].update(sig_alg=value))
    pub = pub_file(tmp_path, default_signer)
    keys = {default_signer.key_id: default_signer.public_hex}
    for k in (keys, None):
        res = verify_all(tmp_path / "l.jsonl", public_keys=k)
        assert res["status"] == "MALFORMED_RECORD" and res["bad_seq"] == 2, (value, k is not None, res)
    for p in (pub, None):
        assert rust(tmp_path / "l.jsonl", p)["status"] == "MALFORMED_RECORD", (value, p)



@pytest.mark.parametrize("value", GOOD_TOKENS)
def test_a_well_formed_unknown_token_is_a_mismatch_not_malformed(tmp_path, default_signer, value):
    """A token inside the grammar is not MALFORMED. Under an Ed25519 key it names an algorithm that key is not
    (BAD_SIGNATURE, D-14); with no keys nothing is checked and the answer is OK."""
    make_ledger(tmp_path / "l.jsonl", default_signer)
    # the LAST record, so that only the claimed algorithm (not a stale later signature) can explain the status
    rewrite(tmp_path / "l.jsonl", lambda r: r[-1].update(sig_alg=value))
    pub = pub_file(tmp_path, default_signer)
    keys = {default_signer.key_id: default_signer.public_hex}
    res = verify_all(tmp_path / "l.jsonl", public_keys=keys)
    assert res["status"] == "BAD_SIGNATURE" and res["bad_seq"] == 3 and "algorithm mismatch" in res["detail"]
    assert verify_all(tmp_path / "l.jsonl")["status"] == "OK"
    r = rust(tmp_path / "l.jsonl", pub)
    assert r["status"] == "BAD_SIGNATURE" and r["bad_seq"] == 3
    assert rust(tmp_path / "l.jsonl")["status"] == "OK"


# ---------------------------------------------------------------- format

@pytest.mark.parametrize("value, expected", [(3, "UNSUPPORTED_FORMAT"), (1, "UNSUPPORTED_FORMAT"), (0, "UNSUPPORTED_FORMAT"),
                                             (-1, "UNSUPPORTED_FORMAT"), (2, "OK"),
                                             ("2", "OK"), (True, "OK"), (None, "OK")])
def test_format_other_than_the_integer_two_is_declined_in_both_languages(tmp_path, default_signer, value, expected):
    make_ledger(tmp_path / "l.jsonl", default_signer)
    rewrite(tmp_path / "l.jsonl", lambda r: r[2].update(format=value))
    res = verify_all(tmp_path / "l.jsonl")
    assert res["status"] == expected, res
    if expected == "UNSUPPORTED_FORMAT":
        assert res["bad_seq"] == 2
    assert rust(tmp_path / "l.jsonl")["status"] == expected


def test_a_missing_format_is_still_legacy_not_unsupported(tmp_path, default_signer):
    make_ledger(tmp_path / "l.jsonl", default_signer)
    rewrite(tmp_path / "l.jsonl", lambda r: r[0].pop("format"))
    assert verify_all(tmp_path / "l.jsonl")["status"] == "LEGACY_FORMAT"
    assert rust(tmp_path / "l.jsonl")["status"] == "LEGACY_FORMAT"


def test_a_tampered_format_value_is_reported_as_tampering_not_as_unsupported(tmp_path, default_signer):
    """Changing `format` without re-hashing breaks the hash first: tamper evidence outranks 'cannot read'."""
    make_ledger(tmp_path / "l.jsonl", default_signer)
    recs = [json.loads(x) for x in (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    recs[2]["format"] = 3
    (tmp_path / "t.jsonl").write_text("".join(_canonical(x) + "\n" for x in recs), encoding="utf-8", newline="\n")
    assert verify_all(tmp_path / "t.jsonl")["status"] == "TAMPERED_LEDGER"
    assert rust(tmp_path / "t.jsonl")["status"] == "TAMPERED_LEDGER"


# ---------------------------------------------------------------- anchors

def anchor_lines(tmp_path, signer, ledger_signer):
    led = make_ledger(tmp_path / "l.jsonl", ledger_signer)
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(tmp_path / "w.jsonl"), signer=signer)
    return [json.loads(x) for x in (tmp_path / "w.jsonl").read_text(encoding="utf-8").splitlines()]



def test_a_non_default_signer_makes_an_anchor_version_3_with_sig_alg_in_the_body(tmp_path, default_signer):
    s = FutureSigner.from_seed(SEED)
    (line,) = anchor_lines(tmp_path, s, default_signer)
    assert line["anchor_version"] == 3 and line["sig_alg"] == "x-future-alg"
    pub = pub_file(tmp_path, default_signer)
    keys = {default_signer.key_id: default_signer.public_hex}
    res = verify_all(tmp_path / "l.jsonl", public_keys=keys, witness_path=tmp_path / "w.jsonl")
    assert res["status"] == "BAD_SIGNATURE" and "algorithm mismatch" in res["detail"]  # an Ed25519 key, another algorithm
    assert rust(tmp_path / "l.jsonl", pub, tmp_path / "w.jsonl")["status"] == "BAD_SIGNATURE"
    # no keys: the anchor's hash and its match with the ledger are still checked
    assert verify_all(tmp_path / "l.jsonl", witness_path=tmp_path / "w.jsonl")["status"] == "OK"
    assert rust(tmp_path / "l.jsonl", None, tmp_path / "w.jsonl")["status"] == "OK"


def _write_anchor(tmp_path, line, rehash_body=True):
    if rehash_body:
        import hashlib

        keys = ("anchor_version", "seq", "head_hash", "prev_anchor", "created_at", "key_id", "sig_alg")
        body = {k: line[k] for k in keys if k in line}
        line["anchor_hash"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    (tmp_path / "w.jsonl").write_text(_canonical(line) + "\n", encoding="utf-8", newline="\n")


@pytest.mark.parametrize("mutation, expected", [
    ("v2-with-sig-alg", "TAMPERED_ANCHOR"),
    ("v3-without-sig-alg", "TAMPERED_ANCHOR"),
    ("v3-explicit-ed25519", "TAMPERED_ANCHOR"),
    ("v3-bad-token", "TAMPERED_ANCHOR"),
    ("v3-token-with-newline", "TAMPERED_ANCHOR"),
    ("v4", "TAMPERED_ANCHOR"),
])
def test_malformed_anchor_shapes_are_tampered_anchor_in_both_languages(tmp_path, default_signer, mutation, expected):
    s = FutureSigner.from_seed(SEED)
    (line,) = anchor_lines(tmp_path, s, default_signer)
    if mutation == "v2-with-sig-alg":
        line["anchor_version"] = 2
    elif mutation == "v3-without-sig-alg":
        line.pop("sig_alg")
    elif mutation == "v3-explicit-ed25519":
        line["sig_alg"] = "ed25519"
    elif mutation == "v3-bad-token":
        line["sig_alg"] = "ES256"
    elif mutation == "v3-token-with-newline":
        line["sig_alg"] = "x-future-alg\n"
    elif mutation == "v4":
        line["anchor_version"] = 4
    _write_anchor(tmp_path, line)
    pub = pub_file(tmp_path, default_signer)
    keys = {default_signer.key_id: default_signer.public_hex}
    for k, p in ((keys, pub), (None, None)):
        res = verify_all(tmp_path / "l.jsonl", public_keys=k, witness_path=tmp_path / "w.jsonl")
        assert res["status"] == expected, (mutation, res)
        assert rust(tmp_path / "l.jsonl", p, tmp_path / "w.jsonl")["status"] == expected, mutation


# ---------------------------------------------------------------- property: the two readers agree on sig_alg values

token_text = st.one_of(
    st.sampled_from(BAD_TOKENS + GOOD_TOKENS),
    st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_ \n\t.", max_size=40),
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(value=token_text, with_keys=st.booleans())
def test_property_python_and_rust_agree_on_any_sig_alg_value(tmp_path_factory, value, with_keys):
    tmp = tmp_path_factory.mktemp("prop")
    s = Signer.from_seed(SEED)
    make_ledger(tmp / "l.jsonl", s, n=3)
    rewrite(tmp / "l.jsonl", lambda r: r[-1].update(sig_alg=value))
    pub = pub_file(tmp, s) if with_keys else None
    keys = {s.key_id: s.public_hex} if with_keys else None
    py = verify_all(tmp / "l.jsonl", public_keys=keys)
    rs = rust(tmp / "l.jsonl", pub)
    assert py["status"] == rs["status"], (value, with_keys, py, rs)
    assert py.get("bad_seq") == rs.get("bad_seq")
    # and never a quiet OK for an algorithm that was not checked while keys were required; under an Ed25519 key
    # (the only kind a file can give) it is not even inconclusive: the claimed algorithm is a mismatch (D-14)
    if with_keys:
        assert py["status"] not in ("OK", "UNSUPPORTED_ALGORITHM", "UNSUPPORTED_FORMAT")


# ---------------------------------------------------------------- R-1: inconclusive never outranks definite evidence
#
# UNSUPPORTED_* can be provoked by anyone who can rewrite the file (add a sig_alg, set format to 3), so it must
# not hide what a witness or a signature can still show.

DEFINITE = {"TAMPERED_LEDGER", "BAD_SIGNATURE", "UNSIGNED_RECORD", "UNKNOWN_KEY", "TAMPERED_ANCHOR",
            "UNSIGNED_ANCHOR", "REWRITTEN", "TRUNCATED", "SINK_MISMATCH"}
INCONCLUSIVE_STATUSES = {"UNSUPPORTED_ALGORITHM", "UNSUPPORTED_FORMAT"}


def witnessed_ledger(tmp_path, signer, n=6):
    led = make_ledger(tmp_path / "l.jsonl", signer, n=n)
    anchor_ledger(led, tmp_path / "a.jsonl", sink=FileSink(tmp_path / "w.jsonl"), signer=signer)
    return n


@pytest.mark.parametrize("where", ["middle", "last"])
@pytest.mark.parametrize("extra", [{"sig_alg": "x-future-alg"}, {"format": 3}, {"sig_alg": "es256", "format": 3}],
                         ids=["sig_alg", "format3", "both"])
@pytest.mark.parametrize("inputs", ["keys+witness", "witness-only", "keys-only"])
def test_r1_an_edit_with_an_inconclusive_marker_is_still_reported_as_evidence(tmp_path, default_signer, where, extra, inputs):
    witnessed_ledger(tmp_path, default_signer)
    index = 2 if where == "middle" else -1
    rewrite(tmp_path / "l.jsonl", lambda r: r[index].update({"decision": "allow", "reason": None, **extra}))
    keys = {default_signer.key_id: default_signer.public_hex} if "keys" in inputs else None
    witness = tmp_path / "w.jsonl" if "witness" in inputs else None
    pub = pub_file(tmp_path, default_signer) if keys else None
    py = verify_all(tmp_path / "l.jsonl", public_keys=keys, witness_path=witness)
    rs = rust(tmp_path / "l.jsonl", pub, witness)
    assert py["status"] == rs["status"], (py, rs)
    assert py.get("bad_seq") == rs.get("bad_seq")
    assert py["status"] not in INCONCLUSIVE_STATUSES, (where, extra, inputs, py)  # D-14: never, with a file key
    if witness is not None:
        # a witness copy of the real head is present: the rewrite must be found, never "could not judge"
        assert py["status"] in DEFINITE, (where, extra, inputs, py)
    if inputs == "keys-only" and where == "middle":
        assert py["status"] in DEFINITE  # the following records' signatures no longer match their new hashes



def test_r1_with_keys_only_and_nothing_after_the_edit_the_status_is_a_mismatch(tmp_path, default_signer):
    """The case a key alone used to leave inconclusive: the LAST record edited and given a sig_alg. D-14 makes it
    definite: an Ed25519 key cannot have signed under another algorithm."""
    witnessed_ledger(tmp_path, default_signer)
    rewrite(tmp_path / "l.jsonl", lambda r: r[-1].update(decision="allow", reason=None, sig_alg="x-future-alg"))
    keys = {default_signer.key_id: default_signer.public_hex}
    res = verify_all(tmp_path / "l.jsonl", public_keys=keys)
    assert res["status"] == "BAD_SIGNATURE" and res["bad_seq"] == 5 and "algorithm mismatch" in res["detail"]
    r = rust(tmp_path / "l.jsonl", pub_file(tmp_path, default_signer))
    assert r["status"] == "BAD_SIGNATURE" and r["bad_seq"] == 5



def test_r1_a_definite_status_found_later_outranks_an_earlier_inconclusive_one(tmp_path):
    """Kept from R-1; with D-14 the inconclusive status is reachable only for a key registered as that type, so
    this runs on the Python API (the Rust verifier cannot be given such a key)."""
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s, n=5)  # every record names x-future-alg: inconclusive from seq 0
    recs = [json.loads(x) for x in (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()]
    recs[3]["decision"] = "deny"  # hash not recomputed
    (tmp_path / "e.jsonl").write_text("".join(_canonical(x) + "\n" for x in recs), encoding="utf-8", newline="\n")
    res = verify_all(tmp_path / "e.jsonl", public_keys=registered_as_future(s))
    assert res["status"] == "TAMPERED_LEDGER" and res["bad_seq"] == 3



def test_r1_coverage_is_reported_with_the_inconclusive_result(tmp_path):
    s = FutureSigner.from_seed(SEED)
    anchor_lines(tmp_path, s, s)
    res = verify_all(tmp_path / "l.jsonl", public_keys=registered_as_future(s), witness_path=tmp_path / "w.jsonl")
    assert res["status"] == "UNSUPPORTED_ALGORITHM"
    assert res["anchored_upto"] == 3 and res["unanchored_tail"] == 0
    assert res["unchecked_algorithms"] == ["x-future-alg"]


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(index=st.integers(0, 5), field=st.sampled_from(["decision", "reason", "tool", "agent_id"]),
       token=st.sampled_from(["x-future-alg", "es256", "a", "ml-dsa-65", None]),
       fmt=st.sampled_from([None, 0, 1, 3, 99]), with_keys=st.booleans())
def test_property_with_a_witness_an_edit_is_never_degraded_to_inconclusive(tmp_path_factory, index, field, token, fmt,
                                                                           with_keys):
    tmp = tmp_path_factory.mktemp("r1")
    s = Signer.from_seed(SEED)
    witnessed_ledger(tmp, s)
    extra = {}
    if token is not None:
        extra["sig_alg"] = token
    if fmt is not None:
        extra["format"] = fmt
    rewrite(tmp / "l.jsonl", lambda r: r[index].update({field: "EDITED", **extra}))
    keys = {s.key_id: s.public_hex} if with_keys else None
    pub = pub_file(tmp, s) if with_keys else None
    py = verify_all(tmp / "l.jsonl", public_keys=keys, witness_path=tmp / "w.jsonl")
    rs = rust(tmp / "l.jsonl", pub, tmp / "w.jsonl")
    assert py["status"] == rs["status"], (py, rs)
    assert py["status"] not in INCONCLUSIVE_STATUSES and py["status"] != "OK", py


# ---------------------------------------------------------------- R-3: anchors' algorithms are named too

def test_r3_a_version_3_anchor_names_its_algorithm_in_the_unchecked_list_without_keys(tmp_path, default_signer):
    s = FutureSigner.from_seed(SEED)
    anchor_lines(tmp_path, s, default_signer)  # ledger signed ed25519, anchor says x-future-alg
    res = verify_all(tmp_path / "l.jsonl", witness_path=tmp_path / "w.jsonl")
    assert res["status"] == "OK" and res["unchecked_algorithms"] == ["x-future-alg"]
    assert any("x-future-alg" in n and "anchors" in n for n in res["notes"])
    r = rust(tmp_path / "l.jsonl", None, tmp_path / "w.jsonl")
    assert r["status"] == "OK" and r["unchecked_algorithms"] == ["x-future-alg"]
    res2 = verify_all(tmp_path / "l.jsonl", anchors_path=tmp_path / "a.jsonl", sinks={"file": FileSink(tmp_path / "w.jsonl")})
    assert res2["status"] == "OK" and res2["unchecked_algorithms"] == ["x-future-alg"]


def test_r3_the_cli_prints_the_algorithm_name_when_it_could_not_check_it(tmp_path, default_signer, capsys):
    from auditrail.cli import main

    s = FutureSigner.from_seed(SEED)
    anchor_lines(tmp_path, s, default_signer)
    assert main(["verify", str(tmp_path / "l.jsonl"), "--witness-file", str(tmp_path / "w.jsonl")]) == 0
    assert "x-future-alg" in capsys.readouterr().out


# ---------------------------------------------------------------- D-14: the mismatch rule, as a property

@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(value=token_text, index=st.integers(0, 3), with_witness=st.booleans())
def test_property_under_an_ed25519_key_any_non_default_sig_alg_is_never_ok_and_never_inconclusive(
        tmp_path_factory, value, index, with_witness):
    tmp = tmp_path_factory.mktemp("d14")
    s = Signer.from_seed(SEED)
    witnessed_ledger(tmp, s, n=4)
    rewrite(tmp / "l.jsonl", lambda r: r[index].update(sig_alg=value))
    keys = {s.key_id: s.public_hex}
    witness = tmp / "w.jsonl" if with_witness else None
    py = verify_all(tmp / "l.jsonl", public_keys=keys, witness_path=witness)
    rs = rust(tmp / "l.jsonl", pub_file(tmp, s), witness)
    assert py["status"] == rs["status"], (value, py, rs)
    assert py["status"] not in ("OK", "UNSUPPORTED_ALGORITHM", "UNSUPPORTED_FORMAT"), (value, py)


def test_the_verifier_reports_the_registered_type_it_found_for_a_key(tmp_path):
    s = FutureSigner.from_seed(SEED)
    make_ledger(tmp_path / "l.jsonl", s)
    # ledger written under 'x-future-alg' but the trusted key is registered as ed25519: a mismatch both ways round
    trusted = TrustedKeys({s.key_id: s.public_hex}, {s.key_id: "ed25519"})
    assert verify_all(tmp_path / "l.jsonl", public_keys=trusted)["status"] == "BAD_SIGNATURE"
