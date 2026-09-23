NAME = "My Formula Template"
VERSION = "0.1.0"
DESCRIPTION = ("Copy this file to NNN_my_formula.py. State what mathematical "
               "idea you are testing, honestly.")
CATEGORY = "Experimental"
TAGS = ["template"]

# Declare ONLY what you truly implement. The runner re-verifies random-access
# claims by measuring cost vs offset — lying here produces "NOT TRUE RANDOM
# ACCESS" in the UI, not a fake success.
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = False
SUPPORTS_STREAMING = False

# Optional declared parameters surfaced in the UI. Values arrive via
# PARAMETERS dict at call time.
PARAMETERS = {
    # "k": {"type": "int", "default": 7, "label": "constant k"},
}

# Contract helpers are importable because the backend injects its path.
from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E402


def analyze(INPUT: bytes, PARAMETERS: dict):
    """INPUT -> STATE. STATE MUST be JSON-serializable (dict/list/str/int).
    If you store the raw input inside STATE it will be counted honestly as
    representation size (state_size = serialized bytes) — the lab measures
    leakage rather than hiding it."""
    return {"size": len(INPUT)}


def reconstruct(STATE: dict, SIZE: int, PARAMETERS: dict) -> bytes:
    """STATE (+SIZE) -> bytes. You receive NO access to the original INPUT.
    SIZE is the expected output length (legitimate metadata, like a file's
    length field)."""
    raise FormulaError("implement me")


def read(STATE: dict, OFFSET: int, LENGTH: int, PARAMETERS: dict) -> bytes:
    """Optional true random access. Instrument expensive work:
        abc_formula.ops(offset_evaluations)
    so the probe can classify your access pattern."""
    raise FormulaError("not supported")
