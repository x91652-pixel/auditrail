"""R2: a connection must show the token soon after connecting; idle unauthenticated ones are dropped first."""
import json
import socket
import time

from auditrail import Ledger, RecorderService, RemoteLedger, Signer
from auditrail.recorder import DEFAULT_PREAUTH_TIMEOUT_S

FIELDS = {"agent_id": "a", "session_id": "s", "policy_version": "p", "tool": "t", "categories": [], "args": {},
         "decision": "allow"}


def service(tmp_path, **kw):
    ledger = Ledger(tmp_path / "l.jsonl", signer=Signer.generate(), fsync=False)
    return RecorderService(ledger, token="tok", heartbeat_s=0, **kw).start(), ledger


def closed_by_peer(sock, within):
    sock.settimeout(within)
    try:
        return sock.recv(1) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        return True
    except socket.timeout:
        return False


def test_the_default_is_ten_seconds_and_documented():
    from pathlib import Path

    assert DEFAULT_PREAUTH_TIMEOUT_S == 10.0
    text = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text(encoding="utf-8")
    assert "preauth_timeout_s" in text


def test_a_connection_that_never_shows_the_token_is_closed_at_the_preauth_timeout(tmp_path):
    svc, _ = service(tmp_path, preauth_timeout_s=0.6, connection_timeout_s=300)
    try:
        s = socket.create_connection(("127.0.0.1", svc.address[1]))
        start = time.monotonic()
        assert closed_by_peer(s, 8.0)
        assert time.monotonic() - start < 6, "closed by the pre-auth deadline, not the 300 s idle timeout"
        s.close()
    finally:
        svc.stop()


def test_a_slow_drip_of_bytes_does_not_keep_an_unauthenticated_connection_alive(tmp_path):
    svc, _ = service(tmp_path, preauth_timeout_s=0.8, connection_timeout_s=300)
    try:
        s = socket.create_connection(("127.0.0.1", svc.address[1]))
        end = time.monotonic() + 8
        closed = False
        while time.monotonic() < end and not closed:
            try:
                s.sendall(b"x")  # never a newline
            except OSError:
                closed = True
                break
            time.sleep(0.2)
            s.settimeout(0.01)
            try:
                closed = s.recv(1) == b""
            except socket.timeout:
                pass
            except OSError:
                closed = True
        assert closed, "the deadline is fixed from connecting; sending a byte now and then does not extend it"
        s.close()
    finally:
        svc.stop()


def test_an_authenticated_agent_is_not_affected_by_the_preauth_deadline(tmp_path):
    svc, ledger = service(tmp_path, preauth_timeout_s=0.5)
    remote = RemoteLedger(port=svc.address[1], token="tok")
    try:
        remote.record(**FIELDS)
        time.sleep(1.5)  # far longer than the pre-auth deadline; the connection is idle but authenticated
        remote.record(**FIELDS)
        assert len([r for r in ledger if r["kind"] == "call"]) == 2
    finally:
        remote.close()
        svc.stop()


def test_a_flood_of_idle_unauthenticated_connections_does_not_lock_out_a_real_agent(tmp_path):
    svc, ledger = service(tmp_path, max_connections=20, preauth_timeout_s=300)
    flood = []
    try:
        for _ in range(30):  # more than the limit; the extras are refused or older idle ones are evicted
            try:
                flood.append(socket.create_connection(("127.0.0.1", svc.address[1])))
            except OSError:
                pass
            time.sleep(0.01)
        time.sleep(0.3)
        remote = RemoteLedger(port=svc.address[1], token="tok")
        remote.record(**FIELDS)  # at the limit, an idle unauthenticated connection is dropped to make room
        remote.close()
        assert len([r for r in ledger if r["kind"] == "call"]) == 1
    finally:
        for s in flood:
            s.close()
        svc.stop()


def test_a_flood_of_130_connections_against_the_default_limit(tmp_path):
    svc, ledger = service(tmp_path)  # defaults: 128 connections
    flood = []
    try:
        for _ in range(130):
            try:
                flood.append(socket.create_connection(("127.0.0.1", svc.address[1])))
            except OSError:
                pass
        time.sleep(0.5)
        remote = RemoteLedger(port=svc.address[1], token="tok")
        remote.record(**FIELDS)
        remote.close()
        assert len([r for r in ledger if r["kind"] == "call"]) == 1
    finally:
        for s in flood:
            s.close()
        svc.stop()


def test_authenticated_connections_are_not_evicted_to_make_room(tmp_path):
    svc, ledger = service(tmp_path, max_connections=2, preauth_timeout_s=300)
    try:
        agents = [RemoteLedger(port=svc.address[1], token="tok") for _ in range(2)]
        for a in agents:
            a.record(**FIELDS)
        third = socket.create_connection(("127.0.0.1", svc.address[1]))
        assert closed_by_peer(third, 5.0), "everyone else is authenticated: the newcomer is refused"
        third.close()
        for a in agents:
            a.record(**FIELDS)  # still connected, still working
        assert len([r for r in ledger if r["kind"] == "call"]) == 4
        for a in agents:
            a.close()
    finally:
        svc.stop()
