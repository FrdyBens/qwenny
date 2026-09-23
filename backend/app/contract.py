"""ABC-INFINITY Formula Lab — the formula API contract.

Every file in formulas/*.py must satisfy this contract. The backend validates
formulas against it before loading; invalid formulas are rejected without
crashing the registry.

Contract
--------
Required metadata (module-level constants):
    NAME        str
    VERSION     str
    DESCRIPTION str            what the experiment tests, stated honestly
    CATEGORY    str            e.g. Baseline / Arithmetic / Algebra / ...

Optional metadata:
    TAGS        list[str]
    PARAMETERS  dict[str, dict]  declared params: {"type","default","label",...}
    ANALYZE_TIMEOUT_S float      per-call wall-clock guard (default 20s)

Capability flags (declare truthfully; the runner re-verifies them):
    SUPPORTS_ANALYSIS        bool
    SUPPORTS_RECONSTRUCTION  bool
    SUPPORTS_RANDOM_ACCESS   bool
    SUPPORTS_STREAMING       bool

Operations (at least analyze + one of reconstruct/read required to be useful;
missing ops are reported as unsupported, never faked):
    analyze(INPUT: bytes, PARAMETERS: dict) -> STATE
        STATE must be JSON-serializable (dict | str | int | float | list).
        Anything non-serializable is treated as hidden state and REJECTED —
        this is the original-data-isolation mechanism: reconstruct()/read()
        only ever receive the deserialized STATE, never the INPUT buffer.

    reconstruct(STATE, SIZE: int, PARAMETERS: dict) -> bytes
    read(STATE, OFFSET: int, LENGTH: int, PARAMETERS: dict) -> bytes
        read() MUST NOT materialize the full output to serve a window if it
        claims random access; instrument with ops():
            import abc_formula
            abc_formula.ops(n)   # count states evaluated / recurrence steps
        The runner records ops-per-read vs offset. If cost grows with OFFSET
        the UI shows "NOT TRUE RANDOM ACCESS".

Errors: raise FormulaError("message") for controlled failures; anything else
is caught by the runner and reported as ERROR (never hidden).
"""
from __future__ import annotations

REQUIRED_META = ("NAME", "VERSION", "DESCRIPTION", "CATEGORY")
CAPABILITY_KEYS = (
    "supports_analysis",
    "supports_reconstruction",
    "supports_random_access",
    "supports_streaming",
)

DEFAULT_ANALYZE_TIMEOUT_S = 20.0


class FormulaError(Exception):
    """Raise inside a formula for a controlled, reported failure."""


def json_safe(obj) -> tuple[bool, str | None]:
    """Return (ok, reason). STATE must survive a JSON round-trip so that no
    live Python object (e.g. a closure over the original bytes) can leak into
    the reconstruction phase."""
    import json

    try:
        s = json.dumps(obj)
        json.loads(s)
        return True, None
    except Exception as e:  # noqa: BLE001
        return False, (
            f"state is not JSON-serializable ({e}); reconstruct/read would "
            "receive hidden live objects (possible source leakage)"
        )
