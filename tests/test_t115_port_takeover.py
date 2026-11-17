"""0.3.4 item 3 (B-F1): on Windows another program must not be able to share the recorder's port."""
import os
import socket

import pytest

from auditrail import Ledger, RecorderService, Signer


@pytest.mark.skipif(os.name != "nt", reason="SO_REUSEADDR lets a second socket share a listening port only on Windows")
def test_a_second_socket_cannot_take_over_the_recorders_port(tmp_path):
    svc = RecorderService(Ledger(tmp_path / "l.jsonl", signer=Signer.from_seed(bytes(range(32))), fsync=False),
                          port=0, heartbeat_s=0).start()
    port = svc.address[1]
    try:
        a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with pytest.raises(OSError):
            a.bind(("127.0.0.1", port))
        a.close()
    finally:
        svc.stop(inflight_timeout_s=0)


def test_the_recorder_still_restarts_on_a_port_just_released(tmp_path):
    for i in range(2):
        svc = RecorderService(Ledger(tmp_path / f"l{i}.jsonl", signer=Signer.from_seed(bytes(range(32))), fsync=False),
                              port=0, heartbeat_s=0).start()
        svc.stop(inflight_timeout_s=0)


@pytest.mark.skipif(os.name == "nt", reason="POSIX keeps SO_REUSEADDR")
def test_posix_keeps_reuse_address(tmp_path):
    svc = RecorderService(Ledger(tmp_path / "l.jsonl", fsync=False), port=0, heartbeat_s=0)
    try:
        assert svc._server.allow_reuse_address is True
    finally:
        svc._server.server_close()
