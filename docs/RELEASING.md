# Releasing (maintainer notes)

How a release of auditrail is built and uploaded. For how to *check* a published release, see
[SECURITY.md](../SECURITY.md) and the README. This file holds no credentials and must never get any.

## 1. Before building

- The release commit is on `main`, tests are green on CI, and the version is the same in `pyproject.toml`,
  `auditrail.__version__`, `verifier/Cargo.toml` and `verifier/Cargo.lock`.
- The tag `vX.Y.Z` points at that commit. The GitHub Release workflow (`release.yml`) builds the Rust binaries
  and their attestations from the tag.

## 2. Build the Python files from the tag (Linux or WSL)

Build from a clean copy of the tag, not from a working tree:

```bash
mkdir -p ~/rb/src && cd ~/rb
git -C /path/to/auditrail -c core.autocrlf=false archive vX.Y.Z | tar -x -C src
export SOURCE_DATE_EPOCH=$(git -C /path/to/auditrail log -1 --format=%ct vX.Y.Z)
python3 -m venv venv && venv/bin/pip install build twine
venv/bin/python -m build --outdir dist src
```

Notes: `core.autocrlf=false` keeps line endings as in git. With the same `SOURCE_DATE_EPOCH` the wheel comes out
byte-identical on repeat builds; the sdist differs only in tar/gzip timestamps, so build once and upload that one
set.

## 3. Check before uploading

- `venv/bin/twine check --strict dist/*`
- Record the file names, sizes and sha256.
- Compare every `.py`, `.md` and `.toml` file in the wheel and sdist with the tag's files, byte for byte; confirm no
  CRLF (other than in `METADATA`/`PKG-INFO`) and that the files contain no personal data or local paths.
- Install the wheel into a new virtual environment; check `python -c "import auditrail; print(auditrail.__version__)"`
  and `auditrail demo`.

## 4. Upload (the maintainer, personally)

- Use a PyPI API token scoped to this project only, on an account with two-factor authentication.
- `venv/bin/twine upload dist/*`. Type or paste the token at twine's hidden prompt yourself.
- Never put the token on a command line, in a file in this repository, or in any chat or tool window. If a token
  is ever shown anywhere, revoke it at once and make a new one.

## 5. After uploading

- Fetch the files back with `pip download auditrail==X.Y.Z --no-deps` in an empty directory and check that their
  sha256 matches what you built and what PyPI shows.
- Install from PyPI into a fresh environment and run the same checks as in step 3.

PyPI currently has no provenance attestation for these files (see SECURITY.md, "Smaller known issues").
