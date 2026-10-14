"""Helper for test_phase1_defaults.py: receive one envelope in a fresh process, sharing a replay store.

usage: python tests/_replay_worker.py <job.json>
job.json: {"db": path, "envelope": {...}, "registry": {agent: public_hex}, "recipient": agent}
Prints ACCEPTED, or REJECTED: <reason>.
"""
import json
import sys

from auditrail import KeyRegistry
from auditrail.agent_bridge import SignatureError, SqliteReplayGuard, receive_envelope

job = json.loads(open(sys.argv[1], encoding="utf-8").read())
guard = SqliteReplayGuard(job["db"])
try:
    receive_envelope(job["envelope"], KeyRegistry(job["registry"]), job["recipient"], guard)
    print("ACCEPTED")
except SignatureError as exc:
    print(f"REJECTED: {exc}")
