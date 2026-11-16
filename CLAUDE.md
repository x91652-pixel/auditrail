# Working rules for AI coding assistants in this repository

This file is read automatically by Claude Code and similar tools. It states how changes are made here. It is
public: keep it free of personal data, credentials and internal schedules.

## How changes are developed

- **Spec and test vectors first.** For any change in behaviour, first write down the expected behaviour
  (input → output, exit code, error message) and add a test or a vector under `docs/spec/vectors/` that
  fails before the change. Then change the code until it passes.
- Changes to verification results must give the same verdict in the Python package and the Rust verifier
  (`verifier/`). CI checks this with `tests/test_vectors.py`, `tests/test_rust_verifier.py` and
  `tests/test_reader_agreement.py`.
- Every statement in `README.md` and `SECURITY.md` about what the tool does must be backed by a test, a
  vector or a code reference. When a statement stops being true, fix the document in the same change.
- Run the tests that cover your change before committing: `pytest <relevant tests>`; for the verifier,
  `cargo test --locked` in `verifier/`. Paste real output in the report; do not summarise a run you did not do.

## Fixed steps

- After editing `SECURITY.md`, run `python tools/gen_limits.py` and commit the regenerated
  `src/auditrail/_limits.py`. `python tools/gen_limits.py --check` must pass.
- A version bump changes `pyproject.toml`, `auditrail.__version__`, `verifier/Cargo.toml` and
  `verifier/Cargo.lock` together.
- Releases follow `docs/RELEASING.md`. Credentials are never written to files, commands or logs.

## Wording

Do not describe the project with claims it cannot back. Avoid words such as *first, novel, only, standard,
safe, secure, compliant, certified, independent, audited, guarantee* in descriptions of the project,
including as qualifiers. In particular:

- Reviews done by AI assistants working on this project are self-review, not independent review.
- The Rust verifier has the same author as the Python package; do not call it an independent verifier.

## What assistants do and do not do

- One task, one branch, one worktree. Do not touch another task's branch or files.
- The author of a change does not review it; review is done separately.
- Assistants may commit and push their own branch and open **draft** pull requests.
- Assistants do **not** merge pull requests, create or move tags, publish to PyPI or GitHub Releases,
  handle tokens or passwords, or post anything outside this repository. Those steps are the maintainer's.
- Never force-push, rewrite published history, or change git configuration.
- When a design choice is needed (behaviour, format, compatibility), stop and ask rather than decide.
