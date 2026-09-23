"""Internal worker for guarded_tool(isolate=True). Not part of the public API.

Invoked as `python -m auditrail._isolate_worker`: reads one JSON job from
stdin ({"module", "qualname", "args", "kwargs"}), imports the target
function by module + top-level name, calls it, and writes a JSON result to
stdout. Kept as a separate OS process (rather than an in-process thread)
so a hung or crashing tool call cannot take down the caller, and so
ambient environment variables are only what the parent explicitly passed
through (see sandbox.py: secret-looking variables are stripped by default).
"""
from __future__ import annotations

import importlib
import json
import sys


def main() -> int:
    job = json.loads(sys.stdin.read())
    module = importlib.import_module(job["module"])
    fn = getattr(module, job["qualname"])
    try:
        result = fn(*job.get("args", []), **job.get("kwargs", {}))
        sys.stdout.write(json.dumps({"status": "ok", "result": result}))
    except Exception as exc:  # noqa: BLE001 - forwarded to the parent process, not swallowed
        sys.stdout.write(json.dumps({"status": "error", "error": f"{exc.__class__.__name__}: {exc}"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
