"""Honest experiment metrics: comparison, BER, representation size.

Representation size is measured as len(json.dumps(STATE)) — the FULL state
the reconstruction phase actually receives. Since STATE is JSON-forced by the
contract, nothing can hide outside it. The original INPUT is never counted
in, but neither can the formula smuggle it into reconstruction.
"""
from __future__ import annotations

import json
from typing import Any


def bit_errors(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    pop = int.bit_count
    return sum(pop(x ^ y) for x, y in zip(a[:n], b[:n])) + \
        (8 * abs(len(a) - len(b)))


def compare(expected: bytes, generated: bytes) -> dict[str, Any]:
    """Exact comparison with first-mismatch diagnostics. Empty-vs-empty on a
    zero-length window is NOT reported as match without sizes agreeing."""
    exact = expected == generated
    res: dict[str, Any] = {
        "expected_size": len(expected),
        "generated_size": len(generated),
        "exact_match": exact,
        "first_mismatch_byte": None,
        "first_mismatch_bit": None,
        "expected_byte_at_mismatch": None,
        "generated_byte_at_mismatch": None,
        "bit_error_rate": None,
    }
    if not exact:
        n = min(len(expected), len(generated))
        for i in range(n):
            if expected[i] != generated[i]:
                res["first_mismatch_byte"] = i
                res["first_mismatch_bit"] = i * 8
                res["expected_byte_at_mismatch"] = expected[i]
                res["generated_byte_at_mismatch"] = generated[i]
                break
        else:
            # common prefix equal; length differs
            if len(expected) != len(generated):
                res["first_mismatch_byte"] = n
                res["first_mismatch_bit"] = n * 8
        total_bits = max(len(expected), len(generated)) * 8
        if total_bits:
            res["bit_error_rate"] = round(bit_errors(expected, generated)
                                          / total_bits, 6)
        else:
            res["bit_error_rate"] = 0.0
    else:
        res["bit_error_rate"] = 0.0
    return res


def state_size(state: Any) -> int:
    """Serialized size in bytes of the honest, JSON-only state."""
    try:
        return len(json.dumps(state, separators=(",", ":")).encode("utf-8"))
    except Exception:  # noqa: BLE001
        return -1


def ratio(input_size: int, rep_size: int) -> float | None:
    if input_size <= 0 or rep_size < 0:
        return None
    return round(rep_size / input_size, 6)
