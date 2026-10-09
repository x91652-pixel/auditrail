"""Internal worker for guarded_tool(isolate=True). Not part of the public API.

Invoked as `python -m auditrail._isolate_worker`: reads one JSON job from
stdin ({"module", "qualname", "args", "kwargs", optional "path"}), imports the
target function by module + top-level name (or, for a function defined in a
script run as __main__, loads that script by path), calls it, and writes one
JSON result line to stdout prefixed with RESULT_MARKER.

Anything the tool itself prints goes to stderr instead (sys.stdout is swapped
during the call), and the parent only trusts the marked line, so a chatty tool
cannot corrupt or forge the result.

Kept as a separate OS process (rather than an in-process thread) so a hung or
crashing tool call cannot take down the caller, and so ambient environment
variables are only what the parent explicitly passed through (see sandbox.py).
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import sys

RESULT_MARKER = "@@auditrail-result@@"  # sandbox.py has the same constant


def _load(job: dict):
    if job.get("path"):
        spec = importlib.util.spec_from_file_location("__auditrail_script__", job["path"])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # a script's `if __name__ == "__main__":` block does not run
    else:
        module = importlib.import_module(job["module"])
    return getattr(module, job["qualname"])


def main() -> int:
    job = json.loads(sys.stdin.read())
    real_stdout = sys.stdout
    sys.stdout = sys.stderr  # tool output must never mix with the result line
    try:
        fn = _load(job)
        result = fn(*job.get("args", []), **job.get("kwargs", {}))
        line = json.dumps({"status": "ok", "result": result})
    except Exception as exc:  # noqa: BLE001 - forwarded to the parent process, not swallowed
        line = json.dumps({"status": "error", "error": f"{exc.__class__.__name__}: {exc}"})
    finally:
        sys.stdout = real_stdout
    real_stdout.write("\n" + RESULT_MARKER + line + "\n")
    real_stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
