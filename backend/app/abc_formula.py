"""Tiny instrumentation module importable by formulas.

Formulas do `import abc_formula` (the registry injects this directory into
sys.path before exec'ing formula code). They call abc_formula.ops(n) to
report how many elementary evaluations a read()/reconstruct() performed.

The runner resets the counter around each timed call, so instrumentation is
per-operation and cannot leak between calls or threads.
"""
import threading

_local = threading.local()


def reset() -> None:
    _local.ops = 0


def ops(n: int = 1) -> None:
    _local.ops = getattr(_local, "ops", 0) + n


def get() -> int:
    return int(getattr(_local, "ops", 0))
