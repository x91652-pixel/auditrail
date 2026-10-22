"""T-036 R-4: `auditrail report` failures are one-line errors with exit 2, and nothing partial is left behind."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from auditrail import Ledger, Signer

ROOT = Path(__file__).resolve().parents[1]
SEED = bytes(range(32))


@pytest.fixture
def env(tmp_path):
    signer = Signer.from_seed(SEED)
    led = Ledger(tmp_path / "l.jsonl", signer=signer, fsync=False)
    for i in range(2):
        led.record(agent_id="a", session_id="s", policy_version="p", policy_hash="ab" * 32, tool="x",
                   categories=["c"], args={"i": i}, decision="allow")
    (tmp_path / "k.pub").write_text(signer.public_hex + "\n", encoding="utf-8")
    return tmp_path


def run(*argv, cwd=None):
    r = subprocess.run([sys.executable, "-m", "auditrail.cli", "report", *map(str, argv)], cwd=cwd or ROOT,
                       capture_output=True, timeout=120)
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace")


def one_line_error(err):
    lines = [x for x in err.splitlines() if x.strip()]
    assert len(lines) == 1, err
    assert lines[0].startswith("[ERROR]")
    assert "Traceback" not in err


def test_out_is_a_directory(env):
    (env / "d").mkdir()
    code, out, err = run(env / "l.jsonl", "--out", env / "d")
    assert code == 2 and out == b""
    one_line_error(err)


def test_out_parent_is_a_file(env):
    code, out, err = run(env / "l.jsonl", "--out", env / "k.pub" / "r.md")
    assert code == 2
    one_line_error(err)


def test_out_parent_does_not_exist_is_not_created(env):
    code, out, err = run(env / "l.jsonl", "--out", env / "nope" / "r.md")
    assert code == 2 and not (env / "nope").exists()
    one_line_error(err)


@pytest.mark.skipif(os.name == "nt", reason="read-only directories are not enforced the same way on Windows")
def test_out_in_a_read_only_directory(env):
    d = env / "ro"
    d.mkdir()
    d.chmod(0o500)
    try:
        if os.access(d, os.W_OK):
            pytest.skip("running with rights that ignore directory permissions")
        code, out, err = run(env / "l.jsonl", "--out", d / "r.md")
        assert code == 2
        one_line_error(err)
    finally:
        d.chmod(0o700)


def test_format_all_writes_nothing_when_one_target_is_unusable(env):
    (env / "r.html").mkdir()
    code, out, err = run(env / "l.jsonl", "--format", "all", "--out", env / "r")
    assert code == 2
    one_line_error(err)
    assert not (env / "r.md").exists() and not (env / "r.json").exists()


def test_existing_out_is_refused_without_force_and_replaced_with_it(env):
    target = env / "r.md"
    target.write_text("old", encoding="utf-8")
    code, out, err = run(env / "l.jsonl", "--out", target)
    assert code == 2 and target.read_text(encoding="utf-8") == "old"
    one_line_error(err)
    assert "--force" in err
    code, out, err = run(env / "l.jsonl", "--out", target, "--force")
    assert code in (0, 1) and target.read_text(encoding="utf-8").startswith("# auditrail verification report")
    assert "replaced the existing file" in out.decode("utf-8")


def test_out_may_never_be_an_input_even_with_force(env):
    before = (env / "l.jsonl").read_bytes()
    code, out, err = run(env / "l.jsonl", "--out", env / "l.jsonl", "--force")
    assert code == 2 and (env / "l.jsonl").read_bytes() == before
    one_line_error(err)


@pytest.mark.parametrize("flag,value", [("--max-gap", "0"), ("--max-gap", "-5"), ("--max-rows", "0"),
                                        ("--max-rows", "-1"), ("--max-rows", "abc"), ("--max-gap", "1.5")])
def test_non_positive_or_non_integer_limits_are_exit_2(env, flag, value):
    code, out, err = run(env / "l.jsonl", flag, value)
    assert code == 2 and out == b""
    assert "Traceback" not in err


def test_missing_input_and_bad_generated_at_are_exit_2_not_1(env):
    assert run(env / "nope.jsonl")[0] == 2
    assert run(env / "l.jsonl", "--generated-at", "yesterday")[0] == 2


def test_stdout_is_the_same_bytes_as_a_file_with_lf_only(env):
    code, out, err = run(env / "l.jsonl", "--pubkey", env / "k.pub")
    assert code in (0, 1)
    assert b"\r\n" not in out
    code2, _, _ = run(env / "l.jsonl", "--pubkey", env / "k.pub", "--out", env / "o.md")
    assert code2 == code
    assert (env / "o.md").read_bytes() == out


def test_stdout_is_utf8_even_when_the_console_encoding_is_not(env):
    e = {**os.environ, "PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"}
    r = subprocess.run([sys.executable, "-m", "auditrail.cli", "report", str(env / "l.jsonl"), "--title", "中文"],
                       cwd=ROOT, capture_output=True, env=e, timeout=120)
    assert r.returncode in (0, 1), r.stderr
    assert "中文".encode("utf-8") in r.stdout
    assert b"Traceback" not in r.stderr


def test_a_read_only_existing_file_with_force_is_a_one_line_error(env):
    import stat

    target = env / "ro.md"
    target.write_text("old", encoding="utf-8")
    target.chmod(stat.S_IREAD)
    try:
        if os.access(target, os.W_OK):
            pytest.skip("running with rights that ignore file permissions")
        code, out, err = run(env / "l.jsonl", "--out", target, "--force")
        assert code == 2 and target.read_text(encoding="utf-8") == "old"
        one_line_error(err)
    finally:
        target.chmod(stat.S_IWRITE | stat.S_IREAD)


# --- T-038 C-1: another name for an input is still the input
def _sha(p):
    import hashlib

    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


@pytest.mark.parametrize("input_role", ["ledger", "pubkey", "witness", "peer"])
def test_c1_no_alias_of_an_input_is_overwritten_even_with_force(env, input_role):
    victim = {"ledger": "l.jsonl", "pubkey": "k.pub", "witness": "w.jsonl", "peer": "p.jsonl"}[input_role]
    if victim in ("w.jsonl", "p.jsonl"):
        (env / victim).write_bytes((env / "l.jsonl").read_bytes())
    extra = {"ledger": [], "pubkey": ["--pubkey", env / "k.pub"], "witness": ["--witness-file", env / "w.jsonl"],
             "peer": ["--peer-ledger", env / "p.jsonl"]}[input_role]
    tmp_link = env / ("hard_" + victim)
    cases = {}
    try:
        os.link(env / victim, tmp_link)
        cases["hardlink"] = tmp_link
    except OSError:
        pass
    cases["same path, another spelling"] = env / "." / victim
    if os.name == "nt":
        cases["case variant"] = env / victim.upper()
        cases["extended prefix"] = Path("\\?\\" + str(env / victim))
        import ctypes

        buf = ctypes.create_unicode_buffer(520)
        if ctypes.windll.kernel32.GetShortPathNameW(str(env / victim), buf, 520) and buf.value:
            cases["8.3 short name"] = Path(buf.value)
    assert cases
    before = _sha(env / victim)
    for label, alias in cases.items():
        code, out, err = run(env / "l.jsonl", *extra, "--out", alias, "--force")
        assert code == 2, (label, err)
        assert _sha(env / victim) == before, label
        one_line_error(err)


def test_c1_symlink_to_the_ledger(env):
    try:
        os.symlink(env / "l.jsonl", env / "sym.md")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available to this account")
    before = _sha(env / "l.jsonl")
    code, out, err = run(env / "l.jsonl", "--out", env / "sym.md", "--force")
    assert code == 2 and _sha(env / "l.jsonl") == before


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows feature")
def test_c1_a_junction_directory_to_the_input_folder(env):
    (env / "sub").mkdir()
    (env / "sub" / "a.jsonl").write_bytes((env / "l.jsonl").read_bytes())
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(env / "jn"), str(env / "sub")], capture_output=True)
    if r.returncode != 0:
        pytest.skip("cannot create a junction")
    before = _sha(env / "sub" / "a.jsonl")
    code, out, err = run(env / "sub" / "a.jsonl", "--out", env / "jn" / "a.jsonl", "--force")
    assert code == 2 and _sha(env / "sub" / "a.jsonl") == before


def test_c1_format_all_targets_are_each_checked_against_the_inputs(env):
    # PREFIX.json is the input ledger's own name: the ledger must not be replaced by the JSON report.
    (env / "r.json").write_bytes((env / "l.jsonl").read_bytes())
    before = _sha(env / "r.json")
    code, out, err = run(env / "r.json", "--format", "all", "--out", env / "r", "--force")
    assert code == 2 and _sha(env / "r.json") == before
    assert not (env / "r.md").exists() and not (env / "r.html").exists()


# --- T-029: a malformed public key file is a one-line error with exit 2 in every command
def _cli(*argv):
    r = subprocess.run([sys.executable, "-m", "auditrail.cli", *map(str, argv)], cwd=ROOT, capture_output=True, timeout=120)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


BAD_KEYS = {
    "bom": (b"\xef\xbb\xbf" + b"ab" * 32 + b"\n", "byte order mark"),
    "utf16": ("ab" * 32 + "\n").encode("utf-16"), 
    "short": (b"ab" * 10, "found 20 hexadecimal digits"),
    "long": (b"ab" * 40, "found 80 hexadecimal digits"),
    "words": (b"not a key", "exactly 64 hexadecimal digits"),
    "empty": (b"", "exactly 64 hexadecimal digits"),
}


@pytest.mark.parametrize("name", sorted(BAD_KEYS))
@pytest.mark.parametrize("command", ["verify", "report", "reconcile"])
def test_malformed_public_key_is_one_line_and_exit_2(env, name, command):
    content = BAD_KEYS[name]
    hint = None
    if isinstance(content, tuple):
        content, hint = content
    (env / "bad.pub").write_bytes(content)
    argv = {"verify": ["verify", env / "l.jsonl"], "report": ["report", env / "l.jsonl"],
            "reconcile": ["reconcile", env / "l.jsonl"]}[command] + ["--pubkey", env / "bad.pub"]
    code, out, err = _cli(*argv)
    assert code == 2, (out, err)
    text = err.strip()
    assert "Traceback" not in err and "Traceback" not in out
    assert "bad.pub" in text and "64 hexadecimal digits" in text
    assert len([l for l in text.splitlines() if l.strip()]) == 1, text
    if name == "utf16":
        assert "UTF-16" in text
    elif hint:
        assert hint in text


def test_a_missing_public_key_file_is_also_one_line(env):
    code, out, err = _cli("verify", env / "l.jsonl", "--pubkey", env / "nope.pub")
    assert code == 2 and "Traceback" not in err
    assert len([l for l in err.splitlines() if l.strip()]) == 1


def test_a_good_public_key_still_verifies(env):
    code, out, err = _cli("verify", env / "l.jsonl", "--pubkey", env / "k.pub")
    assert code == 0, (out, err)
