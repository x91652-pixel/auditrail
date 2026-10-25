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

import hashlib
import hmac
import json
import os
import select
import socket
import socketserver
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .keys import Signer
from ._schema import RecordRejected, check_call, check_event  # noqa: F401
from .ledger import EVENT_KINDS, EvidenceRecord, Ledger, LedgerTailError, call_fields


# Limits on what the recorder will take from a connection before it has even checked the token. Conservative defaults:
# a call record is a few hundred bytes (arguments and results are digests), so 1 MiB per line is far above any real
# request; an idle client is dropped after 5 minutes (RemoteLedger reconnects by itself); 128 connections is many more
# than the agents on one host that share a recorder. All three are constructor arguments of RecorderService.
DEFAULT_MAX_LINE_BYTES = 1024 * 1024
DEFAULT_CONNECTION_TIMEOUT_S = 300.0
DEFAULT_MAX_CONNECTIONS = 128
DEFAULT_PREAUTH_TIMEOUT_S = 10.0  # a connection must present a valid token within this long of connecting


def _token_matches(supplied: Any, expected: str) -> bool:
    """Constant-time token check.

    Both sides are hashed first, so the comparison is over two equal-length byte
    strings whatever the token's length or characters. (hmac.compare_digest on two
    str objects raises for non-ASCII text, which would reject a correct token.)
    A token that is not a string is simply wrong.
    """
    if not isinstance(supplied, str):
        return False
    a = hashlib.sha256(supplied.encode("utf-8", "surrogatepass")).digest()
    b = hashlib.sha256(expected.encode("utf-8", "surrogatepass")).digest()
    return hmac.compare_digest(a, b)


def _permission_findings_for_start(key_path, ledger_path, anchors_path=None) -> list:
    """Findings about files the recorder depends on being open to other local accounts.

    The recorder listens on a loopback TCP port; there is no socket file. The key
    must be private, the ledger and anchors must not be writable by others. Files that
    do not exist yet (a new ledger) are skipped; a *key* that cannot be checked is
    reported as "unchecked".
    """
    from ._perms import Finding, permission_findings

    out = [Finding(f.kind, f"signing key {f.message}") for f in permission_findings(key_path, "secret")]
    for label, path in (("ledger", ledger_path), ("anchors", anchors_path)):
        if path and Path(path).exists():
            out += [Finding(f.kind, f"{label} {f.message}") for f in permission_findings(path, "writable")]
    return out


def startup_permission_warnings(key_path, ledger_path, anchors_path=None) -> list[str]:
    """The messages of _permission_findings_for_start (kept for callers that only print)."""
    return [f.message for f in _permission_findings_for_start(key_path, ledger_path, anchors_path)]


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
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        connection_timeout_s: float = DEFAULT_CONNECTION_TIMEOUT_S,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        preauth_timeout_s: float = DEFAULT_PREAUTH_TIMEOUT_S,
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
        self.max_line_bytes = int(max_line_bytes)
        self.connection_timeout_s = float(connection_timeout_s)
        self.max_connections = int(max_connections)
        self.preauth_timeout_s = float(preauth_timeout_s)
        self._unauthenticated: dict = {}  # socket -> time connected, for connections that have not shown the token
        self._lock = threading.Lock()
        self._connections = 0
        self._received = 0
        self._written = 0
        self._tools: set[str] = set()
        self._stop = threading.Event()
        service = self

        class Handler(socketserver.StreamRequestHandler):
            timeout = service.connection_timeout_s  # an idle or stalled client is dropped, not waited on forever

            def handle(self) -> None:
                # A fixed deadline from connecting: a client that never shows the token is cut off even if it sends a
                # byte now and then (which would restart a per-read socket timeout every time).
                authed = service.token is None
                deadline = time.monotonic() + service.preauth_timeout_s
                state = {"authed": authed}

                def expire() -> None:
                    if not state["authed"]:
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

                timer = threading.Timer(service.preauth_timeout_s, expire)
                timer.daemon = True
                if not authed:
                    timer.start()
                try:
                    self._serve(authed, deadline, state)
                finally:
                    timer.cancel()

            def _serve(self, authed: bool, deadline: float, state: dict) -> None:
                while True:
                    try:
                        if not authed:  # until a valid token is shown the connection lives on a short, fixed deadline
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                return
                            self.connection.settimeout(min(remaining, service.connection_timeout_s))
                        # at most max_line_bytes (+1 to tell "too long" from "exactly the limit") is ever buffered, and
                        # this happens before the token is checked, so an unauthenticated client cannot make us hold more
                        raw = self.rfile.readline(service.max_line_bytes + 1)
                    except OSError:  # includes the read timeout
                        return
                    if not raw:
                        return
                    if len(raw) > service.max_line_bytes and not raw.endswith(b"\n"):
                        return  # a request line longer than the limit: close the connection
                    try:
                        req = json.loads(raw.decode("utf-8"))
                        if not authed and isinstance(req, dict) and _token_matches(req.get("token"), service.token):
                            authed = True
                            state["authed"] = True
                            with service._lock:
                                service._unauthenticated.pop(self.request, None)
                            self.connection.settimeout(service.connection_timeout_s)
                        reply = service.handle_request(req)
                    except Exception as exc:  # noqa: BLE001 - report to the client, keep serving
                        reply = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                    self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))
                    self.wfile.flush()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def verify_request(self, request, client_address) -> bool:
                with service._lock:
                    if service._connections >= service.max_connections:
                        if not service._unauthenticated:
                            return False  # over the limit and everyone is authenticated: refuse the newcomer
                        # make room by dropping the oldest connection that has not shown the token
                        victim = min(service._unauthenticated, key=service._unauthenticated.get)
                        service._unauthenticated.pop(victim, None)
                        try:
                            victim.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    service._connections += 1
                    if service.token is not None:
                        service._unauthenticated[request] = time.monotonic()
                return True

            def process_request_thread(self, request, client_address) -> None:
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    with service._lock:
                        service._connections -= 1
                        service._unauthenticated.pop(request, None)

        self._server = Server((host, port), Handler)
        self.address = self._server.server_address[:2]

    # ------------------------------------------------------------ requests
    def handle_request(self, req: dict) -> dict:
        try:
            return self._handle(req)
        except Exception as exc:  # noqa: BLE001 - bad input is the client's problem, never ours to crash on
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def _handle(self, req: dict) -> dict:
        if self.token is not None and not _token_matches(req.get("token"), self.token):
            return {"ok": False, "error": "bad or missing token"}
        op = req.get("op")
        if op not in ("call", "event"):
            return {"ok": False, "error": f"unsupported op {op!r} (the recorder only appends)"}
        fields = req.get("fields")
        if fields is None:
            fields = {}
        # Only records of a fixed shape are signed, and those a client asked for are marked origin="client" (inside
        # the signature). A request that is refused here is not counted as a call the recorder received.
        if op == "call":
            check_call(fields)
        else:
            check_event(req.get("kind"), fields)
        with self._lock:
            self._received += 1
        try:
            if op == "call":
                rec = self.ledger.append_call(fields, origin="client")
                with self._lock:
                    self._tools.add(rec["tool"])
            else:
                kind = req.get("kind")
                if kind not in EVENT_KINDS:
                    return {"ok": False, "error": f"unsupported event kind {kind!r}"}
                rec = self.ledger.record_event(kind, origin="client", **fields)
        except BaseException:
            # The record was not written and the client is told so: it is not a call the recorder took in and lost, so
            # it must not show up as received-but-not-written in the recorder's own heartbeat.
            with self._lock:
                self._received -= 1
            raise
        with self._lock:
            self._written += 1
        return {"ok": True, "seq": rec["seq"], "hash": rec["hash"]}

    # ------------------------------------------------------------ background work
    def heartbeat(self) -> EvidenceRecord:
        with self._lock:
            received, written = self._received, self._written
            self._received = self._written = 0
            tools = sorted(self._tools)
        try:
            return self.ledger.record_heartbeat(
                recorder_id=self.recorder_id, tools=tools, policy_version=self.policy_version,
                policy_hash=self.policy_hash, calls_attempted=received, calls_recorded=written,
                interval_s=self.heartbeat_s,
            )
        except BaseException:
            with self._lock:  # not written: the counts are still owed to the next heartbeat
                self._received += received
                self._written += written
            raise

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
                # Before the request is on the wire a failure is safe to retry: nothing was processed.
                try:
                    if self._sock is not None and self._peer_closed():
                        self.close()  # an idle connection the recorder already dropped: reconnect, do not fail
                    if self._sock is None:
                        self._sock = socket.create_connection(self.address, timeout=self.timeout)
                        self._file = self._sock.makefile("rb")
                    self._sock.sendall(line)
                except OSError as exc:
                    self.close()
                    if attempt == 2:
                        raise RecorderUnavailable(f"recorder at {self.address[0]}:{self.address[1]} unreachable: {exc}") from exc
                    continue
                # The request has been sent. From here on a failure is NOT retried: the recorder may already have
                # written the record and only the reply was lost, and sending it again would write it twice.
                try:
                    raw = self._file.readline()
                    if not raw:
                        raise ConnectionError("recorder closed the connection")
                    reply = json.loads(raw.decode("utf-8"))
                except (OSError, ValueError) as exc:
                    self.close()
                    raise RecorderUnavailable(
                        f"outcome unknown: the request was sent to {self.address[0]}:{self.address[1]} but no valid reply "
                        f"came back ({type(exc).__name__}). The call may or may not have been recorded; it was not sent "
                        "again. Check the ledger before repeating it.") from exc
                break
        if not reply.get("ok"):
            raise RecorderUnavailable(f"recorder refused the record: {reply.get('error')}")
        return reply

    def _peer_closed(self) -> bool:
        """True if the recorder has closed (or reset) the idle connection, or sent something unexpected on it.

        select() says "readable" on a socket whose peer closed it; MSG_PEEK then reads nothing off the queue. Both
        steps work on Windows and on POSIX. A reset that happens after this check, in the moment before sendall, is
        not caught here and is reported as an unknown outcome."""
        try:
            readable, _, _ = select.select([self._sock], [], [], 0)
            if not readable:
                return False
            return True  # EOF, a reset, or stray bytes: in every case the connection is not usable for a new request
        except (OSError, ValueError):
            return True

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

    findings = _permission_findings_for_start(args.key, args.ledger, args.anchors)
    loose = [f for f in findings if f.kind == "loose"]
    unchecked = [f for f in findings if f.kind == "unchecked"]
    for f in findings:
        if f.kind == "missing":  # a key that is absent fails below with its own error; a new ledger is created
            print(f"[RECORDER][WARN] {f.message}", flush=True)
    allow = getattr(args, "allow_loose_permissions", False)
    if (loose or unchecked) and not allow:
        for f in loose:
            print(f"[RECORDER][ERROR] {f.message}", flush=True)
        for f in unchecked:
            print(f"[RECORDER][ERROR] {f.message}", flush=True)
        why = []
        if loose:
            why.append("files the recorder depends on are open to other accounts")
        if unchecked:
            why.append("the permission check could not run, and an unknown is treated as unsafe")
        print(f"[RECORDER] REFUSING TO START: {'; '.join(why)}. Fix the cause, or start anyway with "
              "--allow-loose-permissions (loose permissions then become warnings, and an unchecked file is "
              "reported as NOT CHECKED).", flush=True)
        return 2
    for f in loose:
        print(f"[RECORDER][WARN] loose permissions accepted (--allow-loose-permissions): {f.message}", flush=True)
    for f in unchecked:
        print(f"[RECORDER][WARN] NOT CHECKED (accepted with --allow-loose-permissions): {f.message}", flush=True)
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
    if token == "":
        print(f"[RECORDER][WARN] {args.token_env} is set but empty; running WITHOUT a token", flush=True)
        token = None
    if token is None:
        print("[RECORDER][WARN] no token: any local process that can reach the port can write to the ledger. "
              "Set the token environment variable.", flush=True)
    anchor_every = args.anchor_every if args.anchor_every is not None else (300 if args.anchors else 0)
    try:
        svc = RecorderService(
            ledger, port=args.port, token=token, policy_version=policy_version, policy_hash=policy_hash,
            heartbeat_s=args.heartbeat, anchors_path=args.anchors, sink=sink, anchor_s=anchor_every,
        ).start()
    except LedgerTailError as exc:
        # the first heartbeat is the first write, so a ledger that ends in the middle of a line is found here
        print("[ERROR] " + " ".join(str(exc).split()), file=sys.stderr, flush=True)
        return 2
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
            # Short sleeps, not one long one: on Windows a signal handler only runs when the main thread
            # comes back to the interpreter, and time.sleep(3600) is woken by Ctrl+C but not by Ctrl+Break
            # or a console close, so the shutdown path (final heartbeat and anchor) was never reached.
            time.sleep(0.5)
    except KeyboardInterrupt:
        svc.stop()
        print("[RECORDER] stopped; final heartbeat and anchor written", flush=True)
    return 0
