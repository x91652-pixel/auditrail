"""Anchoring: publish the ledger head to a witness the ledger owner cannot rewrite alone.

Implements auditrail-docs/錨定協定.md (v1). The ledger's own hash chain only proves
internal consistency; an anchor records the chain head (seq + hash) at a point in
time, and a witness stores a copy of that anchor outside the ledger's custody.
Anchors contain only hashes and timestamps, never tool arguments or results.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from .ledger import GENESIS_HASH, Ledger, _canonical

ANCHOR_VERSION = 1
NO_PREV_ANCHOR = GENESIS_HASH
BODY_KEYS = ("anchor_version", "seq", "head_hash", "prev_anchor", "created_at")
LINE_KEYS = set(BODY_KEYS) | {"anchor_hash", "sink_ref"}


class AnchorError(Exception):
    """Anchoring refused: empty ledger, broken ledger, or a tampered anchor file."""

    def __init__(self, message: str, bad_seq: Optional[int] = None):
        super().__init__(message)
        self.bad_seq = bad_seq


class SinkUnreachable(Exception):
    """The witness could not be reached or used. Not, by itself, evidence of tampering."""


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _anchor_hash(body: dict) -> str:
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def build_anchor(ledger: Ledger, prev_anchor_hash: str = NO_PREV_ANCHOR) -> dict:
    """Describe the current chain head as an anchor (protocol §3, §4.1, §4.3)."""
    records = list(ledger)
    if not records:
        raise AnchorError("ledger is empty; refusing to anchor (protocol §4.1)")
    ok, bad_seq = ledger.verify()
    if not ok:
        raise AnchorError(
            f"ledger chain is broken at seq={bad_seq}; refusing to anchor (protocol §4.3)",
            bad_seq=bad_seq,
        )
    head = records[-1]
    body = {
        "anchor_version": ANCHOR_VERSION,
        "seq": head["seq"],
        "head_hash": head["hash"],
        "prev_anchor": prev_anchor_hash,
        "created_at": _utc_now(),
    }
    return {**body, "anchor_hash": _anchor_hash(body)}


def _parse_anchors(path: Path) -> tuple[list[dict], Optional[dict]]:
    """Return (anchors, problem). problem is set when the anchor chain (protocol §6.2) breaks."""
    if not path.exists():
        return [], None
    anchors: list[dict] = []
    prev = NO_PREV_ANCHOR
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
            body = {k: rec[k] for k in BODY_KEYS}
        except (ValueError, KeyError, TypeError):
            return anchors, {"status": "TAMPERED_ANCHOR", "line": lineno, "detail": "malformed anchor line"}
        if set(rec) - LINE_KEYS:
            return anchors, {"status": "TAMPERED_ANCHOR", "line": lineno, "detail": "unexpected fields in anchor line"}
        if body["anchor_version"] != ANCHOR_VERSION:
            return anchors, {"status": "TAMPERED_ANCHOR", "line": lineno, "detail": "unsupported anchor_version"}
        if rec.get("anchor_hash") != _anchor_hash(body):
            return anchors, {"status": "TAMPERED_ANCHOR", "line": lineno, "detail": "anchor_hash does not match body"}
        if body["prev_anchor"] != prev:
            return anchors, {"status": "TAMPERED_ANCHOR", "line": lineno, "detail": "prev_anchor does not link to the previous anchor"}
        prev = rec["anchor_hash"]
        anchors.append(rec)
    return anchors, None


def _append_line(path: Path, record: dict) -> None:
    """Append-only write (protocol §4.4). Existing lines are never touched."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(_canonical(record) + "\n")


def anchor_ledger(ledger: Ledger, anchors_path: str | Path, sink: Any = None, push: bool = False) -> dict:
    """Create and record an anchor for the current head, if it is new (protocol §4.2).

    Order matters: the anchor is published to the witness first. The local
    anchors file gets the line (including sink_ref) only after publishing
    succeeds, so a local anchor never claims an external witness it does not have.
    """
    anchors_path = Path(anchors_path)
    existing, problem = _parse_anchors(anchors_path)
    if problem is not None:
        raise AnchorError(f"anchors file fails verification ({problem['detail']} at line {problem['line']}); refusing to append")

    prev_hash = existing[-1]["anchor_hash"] if existing else NO_PREV_ANCHOR
    anchor = build_anchor(ledger, prev_hash)

    if existing and existing[-1]["head_hash"] == anchor["head_hash"] and existing[-1]["seq"] == anchor["seq"]:
        return {"status": "UNCHANGED", "anchor": existing[-1]}

    sink_ref = ""
    if sink is not None:
        published_line = _canonical({k: anchor[k] for k in (*BODY_KEYS, "anchor_hash")})
        sink_ref = sink.publish(published_line)
        if push:
            sink.push()
    record = {**anchor, "sink_ref": sink_ref}
    _append_line(anchors_path, record)
    return {"status": "ANCHORED", "anchor": record}


def _report(status: str, detail: str, anchored_upto=None, unanchored_tail=None, **extra) -> dict:
    return {"status": status, "anchored_upto": anchored_upto, "unanchored_tail": unanchored_tail, "detail": detail, **extra}


def _sink_for(sink_ref: str, sinks: dict) -> Any:
    prefix = sink_ref.split(":", 1)[0]
    return sinks.get(prefix)


def verify_anchors(ledger_path: str | Path, anchors_path: str | Path, sinks: Optional[dict] = None) -> dict:
    """Run the five checks of protocol §6 and report the first failure, or OK with coverage."""
    sinks = sinks or {}
    ledger_path = Path(ledger_path)
    records: list[dict] = []
    if ledger_path.exists():
        ledger = Ledger(ledger_path)
        ok, bad_seq = ledger.verify()  # §6.1
        if not ok:
            return _report("TAMPERED_LEDGER", f"ledger hash chain breaks at seq={bad_seq}", bad_seq=bad_seq)
        records = list(ledger)
    max_seq = records[-1]["seq"] if records else None

    anchors, problem = _parse_anchors(Path(anchors_path))  # §6.2
    if problem is not None:
        return _report(problem["status"], problem["detail"], line=problem["line"])

    by_seq = {r["seq"]: r for r in records}
    for a in anchors:  # §6.3
        rec = by_seq.get(a["seq"])
        if rec is None:
            return _report("TRUNCATED", f"ledger ends at seq={max_seq}, but anchor needs seq={a['seq']}", max_seq=max_seq)
        if rec["hash"] != a["head_hash"]:
            return _report("REWRITTEN", f"record at anchored seq={a['seq']} no longer matches the anchor's head_hash", bad_seq=a["seq"])

    for a in anchors:  # §6.4
        ref = a.get("sink_ref", "")
        if not ref:
            continue
        sink = _sink_for(ref, sinks)
        if sink is None:
            return _report("SINK_UNREACHABLE", f"no sink configured for {ref.split(':', 1)[0]!r}; anchor seq={a['seq']} not checked")
        try:
            found = sink.fetch_contains(ref, a["anchor_hash"])
        except SinkUnreachable as exc:
            return _report("SINK_UNREACHABLE", f"sink unreachable for anchor seq={a['seq']}: {exc}")
        if not found:
            return _report("SINK_MISMATCH", f"witness does not contain anchor seq={a['seq']} (anchor_hash {a['anchor_hash'][:12]}…)", bad_seq=a["seq"])

    anchored_upto = anchors[-1]["seq"] if anchors else None
    tail = len(records) - (anchored_upto + 1) if anchors else len(records)
    external = sum(1 for a in anchors if a.get("sink_ref"))
    detail = f"{len(anchors)} anchor(s) verified; {external} witnessed externally; {tail} record(s) after the last anchor are not covered"
    return _report("OK", detail, anchored_upto=anchored_upto, unanchored_tail=tail)


class FileSink:
    """Local-file witness. For tests only: no external evidentiary value (protocol §5.2)."""

    prefix = "file"

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def publish(self, anchor_line: str) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(anchor_line + "\n")
        return f"file:{self.path.name}"

    def fetch_contains(self, sink_ref: str, anchor_hash: str) -> bool:
        if not self.path.exists():
            return False
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            try:
                if json.loads(raw).get("anchor_hash") == anchor_hash:
                    return True
            except ValueError:
                continue
        return False


class GitSink:
    """Git witness (protocol §5.1). Uses only the `git` executable, via subprocess.

    Anchor lines go to anchors/anchors.jsonl in the given repository. Verification
    reads that file as it is at HEAD, so the witness content, not sink_ref, is what counts.
    """

    prefix = "git"
    RELPATH = "anchors/anchors.jsonl"

    def __init__(self, repo_path: str | Path):
        self.repo = Path(repo_path)

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["git", "-C", str(self.repo), *args],
                capture_output=True, text=True, encoding="utf-8", check=check,
            )
        except FileNotFoundError as exc:
            raise SinkUnreachable("git executable not found") from exc
        except subprocess.CalledProcessError as exc:
            raise SinkUnreachable(f"git {args[0]} failed: {exc.stderr.strip()}") from exc

    def _identity_args(self) -> list[str]:
        """Use the repo's own identity if set; otherwise a fixed anchor identity for this commit only."""
        has_name = self._git("config", "user.name", check=False).returncode == 0
        has_email = self._git("config", "user.email", check=False).returncode == 0
        if has_name and has_email:
            return []
        return ["-c", "user.name=auditrail-anchor", "-c", "user.email=anchor@auditrail.invalid"]

    def publish(self, anchor_line: str) -> str:
        if not self.repo.is_dir():
            raise SinkUnreachable(f"repository path does not exist: {self.repo}")
        self._git("rev-parse", "--git-dir")
        target = self.repo / Path(self.RELPATH)
        target.parent.mkdir(parents=True, exist_ok=True)
        size_before = target.stat().st_size if target.exists() else 0
        with target.open("a", encoding="utf-8") as f:
            f.write(anchor_line + "\n")
        try:
            parsed = json.loads(anchor_line)
            message = f"anchor seq={parsed['seq']} head={parsed['head_hash'][:12]}"
            self._git("add", "--", self.RELPATH)
            self._git(*self._identity_args(), "commit", "-q", "-m", message)
            sha = self._git("rev-parse", "HEAD").stdout.strip()
        except SinkUnreachable:
            # Roll back our own uncommitted append so a retry does not duplicate the line.
            with target.open("r+b") as f:
                f.truncate(size_before)
            self._git("reset", "-q", "--", self.RELPATH, check=False)
            raise
        return f"git:{sha}"

    def push(self, remote: str = "origin") -> None:
        """Only called when the caller explicitly asks for it (anchor --push)."""
        self._git("push", remote, "HEAD")

    def fetch_contains(self, sink_ref: str, anchor_hash: str) -> bool:
        if not self.repo.is_dir():
            raise SinkUnreachable(f"repository path does not exist: {self.repo}")
        self._git("rev-parse", "--git-dir")
        result = self._git("show", f"HEAD:{self.RELPATH}", check=False)
        if result.returncode != 0:
            return False  # no commits, or the anchors file is absent at HEAD
        for raw in result.stdout.splitlines():
            try:
                if json.loads(raw).get("anchor_hash") == anchor_hash:
                    return True
            except ValueError:
                continue
        return False
