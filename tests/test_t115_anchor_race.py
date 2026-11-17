"""0.3.4 item 1 (A-F1): two anchor writers must not corrupt the anchors file, and the recorder must not hide errors."""
import threading
from pathlib import Path

from auditrail import Ledger, RecorderService, Signer
from auditrail.anchor import anchor_ledger
from auditrail.verifier import verify_all


def _ledger(d, signer):
    led = Ledger(d / "l.jsonl", signer=signer)
    led.record(agent_id="a", session_id="s", policy_version="v", tool="t", categories=[], args={}, decision="allow")
    return led


def test_two_concurrent_anchor_writers_leave_a_verifiable_file(tmp_path):
    s = Signer.from_seed(bytes([3]) * 32)
    for i in range(10):
        d = tmp_path / f"r{i}"
        d.mkdir()
        led = _ledger(d, s)
        ap = d / "a.jsonl"
        bar = threading.Barrier(2)
        out = []

        def w():
            bar.wait()
            out.append(anchor_ledger(led, ap, signer=s)["status"])

        ts = [threading.Thread(target=w) for _ in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert sorted(out) == ["ANCHORED", "UNCHANGED"], (i, out)
        assert len([ln for ln in ap.read_text().splitlines() if ln.strip()]) == 1
        assert verify_all(d / "l.jsonl", public_keys={s.key_id: s.public_hex}, anchors_path=ap)["status"] == "OK"


def test_recorder_anchor_on_an_empty_ledger_is_quietly_none(tmp_path, capsys):
    s = Signer.from_seed(bytes([4]) * 32)
    svc = RecorderService(Ledger(tmp_path / "l.jsonl", signer=s), port=0, heartbeat_s=0,
                          anchors_path=str(tmp_path / "a.jsonl"))
    assert svc.anchor() is None
    assert svc.last_anchor_error is None and capsys.readouterr().err == ""
    svc._server.server_close()


def test_recorder_anchor_failure_is_recorded_and_visible(tmp_path, capsys):
    s = Signer.from_seed(bytes([5]) * 32)
    led = _ledger(tmp_path, s)
    ap = tmp_path / "a.jsonl"
    ap.write_text('{"not":"an anchor"}\n', encoding="utf-8")  # an anchors file that fails verification
    svc = RecorderService(led, port=0, heartbeat_s=0, anchors_path=str(ap))
    assert svc.anchor() is None
    assert svc.last_anchor_error and "anchors file fails verification" in svc.last_anchor_error
    assert svc.anchor_errors == 1
    assert "[RECORDER][WARN] anchoring failed" in capsys.readouterr().err
    svc._server.server_close()
