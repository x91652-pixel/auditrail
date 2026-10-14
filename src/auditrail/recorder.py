"""Recorder service: keep the ledger file and the signing key out of the agent's reach.

If the agent process writes its own ledger and holds the key, a compromised
agent (or an operator with the same access) can rewrite its own evidence. The
recorder runs as a separate process -- ideally as a separate OS user that owns
the ledger file and the key -- and accepts only "append this" requests over a
local socket. The agent side (RemoteLedger) has no way to read, edit, or
delete records, and never sees the key.

Protocol: one JSON object per line over TCP on 127.0.0.1.
  {"op": "call",  "fields": {...call_fields()...}, "token": "..."}
  {"op": "event", "kind": "a2a_send" | ..., "fields": {...}, "token": "..."}
  -> {"ok": true, "seq": 12, "hash": "..."}   or   {"ok": false, "error": "..."}

The recorder writes its own heartbeat every heartbeat_s seconds (requests
received vs. written, tools seen, policy hash) and, if configured, signs and
publishes an anchor every anchor_s seconds.

Limits: a local socket is reachable by every process on the host that can
open it; set a token (AUDITRAIL_RECORDER_TOKEN) so only your agents can append.
Running the recorder as the same OS user as the agent gives separation of
process memory only -- the agent could still read the key file from disk.
"""
from __future__ import annotations

import hmac
import json
import os
import socket
import socketserver
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

from .keys import Signer
from .ledger import EVENT_KINDS, EvidenceRecord, Ledger, call_fields


class RecorderService:
    def __init__(
        self,
        ledger: Ledger,
        host: str = "127.0.0.1",
        port: int = 0,
        token: Optional[str] = None,
        policy_version: str = "",
        policy_hash: Optional[str] = None,
        heartbeat_s: int = 60,
        anchors_path: Optional[str] = None,
        sink: Any = None,
        anchor_s: int = 0,
        recorder_id: str = "recorder",
    ):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("the recorder only listens on a loopback address")
        self.ledger = ledger
        self.token = token
        self.policy_version = policy_version
        self.policy_hash = policy_hash
        self.heartbeat_s = heartbeat_s
        self.anchors_path = anchors_path
        self.sink = sink
        self.anchor_s = anchor_s
        self.recorder_id = recorder_id
        self._lock = threading.Lock()
        self._received = 0
        self._written = 0
        self._tools: set[str] = set()
        self._stop = threading.Event()
        service = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                for raw in self.rfile:
                    try:
                        reply = service.handle_request(json.loads(raw.decode("utf-8")))
                    except Exception as exc:  # noqa: BLE001 - report to the client, keep serving
                        reply = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                    self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))
                    self.wfile.flush()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = Server((host, port), Handler)
        self.address = self._server.server_address[:2]

    # ------------------------------------------------------------ requests
    def handle_request(self, req: dict) -> dict:
        try:
            return self._handle(req)
        except Exception as exc:  # noqa: BLE001 - bad input is the client's problem, never ours to crash on
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def _handle(self, req: dict) -> dict:
        if self.token is not None and not hmac.compare_digest(str(req.get("token", "")), self.token):
            return {"ok": False, "error": "bad or missing token"}
        op = req.get("op")
        if op not in ("call", "event"):
            return {"ok": False, "error": f"unsupported op {op!r} (the recorder only appends)"}
        with self._lock:
            self._received += 1
        fields = req.get("fields") or {}
        if op == "call":
            rec = self.ledger.append_call(fields)  # validates the exact field set
            with self._lock:
                self._tools.add(rec["tool"])
        else:
            kind = req.get("kind")
            if kind not in EVENT_KINDS:
                return {"ok": False, "error": f"unsupported event kind {kind!r}"}
            rec = self.ledger.record_event(kind, **fields)
        with self._lock:
            self._written += 1
        return {"ok": True, "seq": rec["seq"], "hash": rec["hash"]}

    # ------------------------------------------------------------ background work
    def heartbeat(self) -> EvidenceRecord:
        with self._lock:
            received, written = self._received, self._written
            self._received = self._written = 0
            tools = sorted(self._tools)
        return self.ledger.record_heartbeat(
            recorder_id=self.recorder_id, tools=tools, policy_version=self.policy_version,
            policy_hash=self.policy_hash, calls_attempted=received, calls_recorded=written,
            interval_s=self.heartbeat_s,
        )

    def anchor(self) -> Optional[dict]:
        if not self.anchors_path:
            return None
        from .anchor import AnchorError, anchor_ledger

        try:
            return anchor_ledger(self.ledger, self.anchors_path, sink=self.sink, signer=self.ledger.signer)
        except AnchorError:
            return None  # empty ledger; nothing to anchor yet

    def _loop(self, interval: int, fn) -> None:
        while not self._stop.wait(interval):
            try:
                fn()
            except Exception:  # noqa: BLE001 - a missed beat/anchor shows up as a gap to the verifier
                pass

    def start(self) -> "RecorderService":
        self.heartbeat()
        threading.Thread(target=self._server.serve_forever, name="auditrail-recorder", daemon=True).start()
        if self.heartbeat_s > 0:
            threading.Thread(target=self._loop, args=(self.heartbeat_s, self.heartbeat), daemon=True).start()
        if self.anchor_s > 0 and self.anchors_path:
            threading.Thread(target=self._loop, args=(self.anchor_s, self.anchor), daemon=True).start()
        return self

    def stop(self) -> None:
        """Final heartbeat and anchor, then shut down."""
        self._stop.set()
        self._server.shutdown()
        self._server.server_close()
        self.heartbeat()
        self.anchor()


class RecorderUnavailable(RuntimeError):
    """The recorder could not be reached. The guarded call's evidence was not written."""


class RemoteLedger:
    """Agent-side stand-in for Ledger that can only append, through a RecorderService.

    Raw arguments and results are reduced to digests here, before anything leaves
    the agent process. If the recorder is unreachable, record() raises
    RecorderUnavailable: a denied call still never runs, and an allowed call that
    already ran raises instead of returning silently (the heartbeat's
    intercepted/recorded counts also show the gap).
    """

    signer = None

    def __init__(self, host: str = "127.0.0.1", port: int = 8765, token: Optional[str] = None, timeout: float = 5.0):
        self.address = (host, port)
        self.token = token if token is not None else os.environ.get("AUDITRAIL_RECORDER_TOKEN")
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._file = None
        self._lock = threading.Lock()

    def _send(self, req: dict) -> dict:
        if self.token:
            req = {**req, "token": self.token}
        line = (json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._sock is None:
                        self._sock = socket.create_connection(self.address, timeout=self.timeout)
                        self._file = self._sock.makefile("rb")
                    self._sock.sendall(line)
                    raw = self._file.readline()
                    if not raw:
                        raise ConnectionError("recorder closed the connection")
                    reply = json.loads(raw.decode("utf-8"))
                    break
                except OSError as exc:
                    self.close()
                    if attempt == 2:
                        raise RecorderUnavailable(f"recorder at {self.address[0]}:{self.address[1]} unreachable: {exc}") from exc
        if not reply.get("ok"):
            raise RecorderUnavailable(f"recorder refused the record: {reply.get('error')}")
        return reply

    def close(self) -> None:
        try:
            if self._file is not None:
                self._file.close()
            if self._sock is not None:
                self._sock.close()
        finally:
            self._sock = self._file = None

    def record(self, **kwargs: Any) -> EvidenceRecord:
        reply = self._send({"op": "call", "fields": call_fields(**kwargs)})
        return EvidenceRecord(seq=reply["seq"], hash=reply["hash"])

    def record_event(self, kind: str, **fields: Any) -> EvidenceRecord:
        reply = self._send({"op": "event", "kind": kind, "fields": fields})
        return EvidenceRecord(seq=reply["seq"], hash=reply["hash"])

    def record_heartbeat(self, **fields: Any) -> EvidenceRecord:
        fields["tools"] = sorted(fields.get("tools", []))
        return self.record_event("heartbeat", **fields)

    def new_session_id(self) -> str:
        return uuid.uuid4().hex[:12]

    def __iter__(self):
        raise TypeError("RemoteLedger is append-only: agents cannot read the ledger")


def serve(args) -> int:
    """Entry point for `auditrail recorder` (blocks until Ctrl+C)."""
    import time

    from .anchor import FileSink, GitSink
    from .policy import PolicyEngine

    signer = Signer.from_file(args.key)
    ledger = Ledger(args.ledger, signer=signer)
    policy_version, policy_hash = "", None  # no policy file: heartbeats say "unknown" rather than inventing a hash
    if args.policy:
        engine = PolicyEngine.from_yaml(args.policy)
        policy_version, policy_hash = engine.version, engine.policy_hash
    sink = None
    if args.git_repo:
        sink = GitSink(args.git_repo)
    elif args.witness_file:
        sink = FileSink(args.witness_file)
    token = os.environ.get(args.token_env) if args.token_env else None
    anchor_every = args.anchor_every if args.anchor_every is not None else (300 if args.anchors else 0)
    svc = RecorderService(
        ledger, port=args.port, token=token, policy_version=policy_version, policy_hash=policy_hash,
        heartbeat_s=args.heartbeat, anchors_path=args.anchors, sink=sink, anchor_s=anchor_every,
    ).start()
    if args.anchors and anchor_every:
        svc.anchor()  # one right away, so a recorder killed early still left something behind
    host, port = svc.address
    print(f"[RECORDER] listening on {host}:{port}; ledger={Path(args.ledger)}; key_id={signer.key_id}"
          f"; token={'required' if token else 'NOT set'}", flush=True)
    import signal

    def _term(*_):
        raise KeyboardInterrupt

    for sig in ("SIGTERM", "SIGBREAK"):  # SIGBREAK is the Windows Ctrl+Break
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), _term)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        svc.stop()
        print("[RECORDER] stopped; final heartbeat and anchor written", flush=True)
    return 0
