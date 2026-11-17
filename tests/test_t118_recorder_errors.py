"""0.3.4 follow-up: anchoring failures of every kind are counted and shown; a busy port is one line and exit 2."""
import argparse
import socket

from auditrail import Ledger, RecorderService, Signer, recorder
from auditrail.anchor import SinkUnreachable


class _BadSink:
    def publish(self, line):
        raise SinkUnreachable("witness is down")

    def fetch(self, ref):
        raise SinkUnreachable("witness is down")


def _svc(tmp_path, sink):
    led = Ledger(tmp_path / "l.jsonl", signer=Signer.from_seed(bytes(range(32))), fsync=False)
    return RecorderService(led, port=0, heartbeat_s=0, anchors_path=str(tmp_path / "a.jsonl"), sink=sink)


def test_an_unreachable_sink_is_counted_and_warned(tmp_path, capsys):
    svc = _svc(tmp_path, _BadSink())
    svc.heartbeat()
    assert svc.anchor() is None
    assert svc.anchor_errors == 1 and "witness is down" in svc.last_anchor_error
    assert "[RECORDER][WARN]" in capsys.readouterr().err
    svc._server.server_close()


def test_an_os_error_is_counted_and_warned(tmp_path, capsys, monkeypatch):
    svc = _svc(tmp_path, None)
    svc.heartbeat()

    def boom(*a, **k):
        raise PermissionError("disk says no")

    monkeypatch.setattr("auditrail.anchor.anchor_ledger", boom)
    assert svc.anchor() is None
    assert svc.anchor_errors == 1 and "disk says no" in svc.last_anchor_error
    assert "[RECORDER][WARN]" in capsys.readouterr().err
    svc._server.server_close()


def test_a_busy_port_is_one_line_and_exit_2(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("T118_TOKEN", "t")
    key, _ = Signer.generate().save(tmp_path / "rec")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        ns = argparse.Namespace(
            key=str(key), ledger=str(tmp_path / "l.jsonl"), port=port, policy=None, heartbeat=0, anchors=None,
            anchor_every=None, witness_file=None, git_repo=None, token_env="T118_TOKEN", allow_loose_permissions=True)
        assert recorder.serve(ns) == 2
    finally:
        s.close()
    err = capsys.readouterr().err
    assert "[RECORDER][ERROR]" in err and str(port) in err and "Traceback" not in err
