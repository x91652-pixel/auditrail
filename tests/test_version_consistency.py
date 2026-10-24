"""One version everywhere: pyproject.toml, auditrail.__version__, the Rust crate and `auditrail-verify --version`."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import auditrail

ROOT = Path(__file__).resolve().parents[1]


def _toml_version(path):
    m = re.search(r'^version\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8"), re.M)
    return m.group(1)


def test_python_package_versions_agree():
    assert auditrail.__version__ == _toml_version(ROOT / "pyproject.toml")


def test_the_rust_crate_and_the_lock_file_have_the_same_version():
    assert _toml_version(ROOT / "verifier" / "Cargo.toml") == auditrail.__version__
    lock = (ROOT / "verifier" / "Cargo.lock").read_text(encoding="utf-8")
    m = re.search(r'name = "auditrail-verify"\nversion = "([^"]+)"', lock)
    assert m and m.group(1) == auditrail.__version__


def test_the_package_has_no_personal_author_data():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'authors = [{ name = "wei chan" }]' in text and "@" not in re.search(r"authors = .*", text).group(0)


CANDIDATES = [ROOT / "verifier" / "target" / "release" / n for n in ("auditrail-verify.exe", "auditrail-verify")]
BINARY = next((p for p in CANDIDATES if p.exists()), None) or shutil.which("auditrail-verify")


@pytest.mark.skipif(BINARY is None, reason="Rust verifier not built")
def test_the_built_verifier_reports_the_same_version():
    out = subprocess.run([str(BINARY), "--version"], capture_output=True, text=True, encoding="utf-8").stdout
    assert out.startswith(f"auditrail-verify {auditrail.__version__} ")
