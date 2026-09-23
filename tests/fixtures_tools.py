"""Module-level helper used by test_sandbox.py's isolate=True test.

Must live at module top level (not inside a test function) because
guarded_tool(isolate=True) runs the wrapped call in a subprocess that
imports it as `module.name`.
"""


def add(a, b):
    return a + b
