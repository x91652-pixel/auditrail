"""F8: RemoteLedger never sends a request twice once it may have reached the recorder."""
import socket
import threading
import time

import pytest

from auditrail import Ledger, RecorderService, RemoteLedger, Signer
from auditrail.recorder import RecorderUnavailable

FIELDS = {"agent_id": "a", "session_id": "s", "policy_version": "p", "tool": "transfer", "categories": [], "args": {},
         "decision": "allow"}


def calls(ledger):
    return [r for r in ledger if r["kind"] == "call"]


class DropFirstReply:
    """A TCP proxy in front of the recorder that forwards requests but throws away the first reply and closes."""

    def __init__(self, target):
        self.target = target
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.dropped = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._pipe, args=(client,), daemon=True).start()

    def _pipe(self, client):
        upstream = socket.create_connection(self.target)
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    return
                upstream.sendall(data)
                reply = upstream.recv(65536)
                if self.dropped == 0:
                    self.dropped = 1
                    return  # the recorder has handled the request; the reply is lost and the connection dropped
                client.sendall(reply)
        except OSError:
            return
        finally:
            for s in (client, upstream):
                try:
                    s.close()
                except OSError:
                    pass

    def close(self):
        self.srv.close()


def test_a_lost_reply_is_reported_as_unknown_and_the_call_is_not_written_twice(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", signer=Signer.generate(), fsync=False)
    svc = RecorderService(ledger, token="t", heartbeat_s=0).start()
    proxy = DropFirstReply(svc.address)
    remote = RemoteLedger(port=proxy.port, token="t")
    try:
        with pytest.raises(RecorderUnavailable) as ei:
            remote.record(**FIELDS)
        msg = str(ei.value)
        assert "outcome unknown" in msg and "may or may not have been recorded" in msg and "Check the ledger" in msg
        assert len(calls(ledger)) == 1, "exactly one record: the request was not sent again"
        remote.record(**FIELDS)  # the next call reconnects and works
        assert len(calls(ledger)) == 2
    finally:
        remote.close()
        proxy.close()
        svc.stop()


def test_an_idle_connection_the_recorder_closed_is_replaced_without_an_error_and_without_a_duplicate(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", signer=Signer.generate(), fsync=False)
    svc = RecorderService(ledger, token="t", heartbeat_s=0, connection_timeout_s=0.4).start()
    remote = RemoteLedger(port=svc.address[1], token="t")
    try:
        remote.record(**FIELDS)
        time.sleep(1.5)  # the recorder drops the idle connection
        remote.record(**FIELDS)  # must reconnect before sending, not fail and not send twice
        assert len(calls(ledger)) == 2
    finally:
        remote.close()
        svc.stop()


def test_a_recorder_that_is_down_is_still_retried_once_and_reported_unreachable(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    remote = RemoteLedger(port=port, token="t", timeout=0.5)
    with pytest.raises(RecorderUnavailable) as ei:
        remote.record(**FIELDS)
    assert "unreachable" in str(ei.value) and "outcome unknown" not in str(ei.value)


def test_a_refusal_from_the_recorder_is_still_reported_as_a_refusal(tmp_path):
    svc = RecorderService(Ledger(tmp_path / "l.jsonl", fsync=False), token="t", heartbeat_s=0).start()
    remote = RemoteLedger(port=svc.address[1], token="wrong")
    try:
        with pytest.raises(RecorderUnavailable, match="token"):
            remote.record(**FIELDS)
    finally:
        remote.close()
        svc.stop()
