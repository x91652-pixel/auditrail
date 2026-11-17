"""Module-level helper used by test_sandbox.py's isolate=True test.

Must live at module top level (not inside a test function) because
guarded_tool(isolate=True) runs the wrapped call in a subprocess that
imports it as `module.name`.
"""


def add(a, b):
    return a + b


def fail_always(x):
    raise ValueError("nope")


def never_runs():
    raise AssertionError("a denied call must never reach the tool body")


def leave_a_child_and_hang(pidfile):
    """Starts a child that inherits the worker's output pipes and sleeps 25 s, then hangs itself."""
    import subprocess
    import sys
    import time

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(25)"])
    with open(pidfile, "w") as f:
        f.write(str(child.pid))
    time.sleep(120)
    return 1
