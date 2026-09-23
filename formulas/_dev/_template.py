"""ABC-INFINITY formula template. Copy to formulas/NNN_my_idea.py and edit.

Contract (validated by the registry on load):
- Required metadata: NAME, VERSION, DESCRIPTION, CATEGORY
- analyze(INPUT: bytes, PARAMETERS: dict) -> JSON-serializable STATE
  * STATE is JSON round-tripped before reconstruction; anything non-JSON
    (closures, buffers) is REJECTED — this prevents source leakage.
  * Do NOT store INPUT (or a hash of it) inside STATE unless this formula
    is an explicit BASELINE control that says so in its description.
- reconstruct(STATE, SIZE, PARAMETERS) -> bytes   (if SUPPORTS_RECONSTRUCTION)
- read(STATE, OFFSET, LENGTH, PARAMETERS) -> bytes (if SUPPORTS_RANDOM_ACCESS)
- Instrument cost with abc_formula.ops(n) so the runner can classify TRUE
  vs simulated random access. Raise FormulaError("...") for controlled
  failures. Never use SHA-256(INPUT) as a seed/state: verification only.
"""
NAME = "My Formula"
VERSION = "0.1.0"
DESCRIPTION = "Experimental mathematical formula. Says what it tests."
CATEGORY = "Experimental"
TAGS = ["experimental"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402,F401
import abc_formula                  # noqa: E402


def analyze(INPUT, PARAMETERS):
    # Fit ONLY mathematical parameters here (tiny state). len(INPUT) is fine.
    return {"size": len(INPUT)}


def _byte(n, STATE):
    # byte(n) = F(parameters, n) — the direct-index ideal.
    return (n * 3 + 5) & 0xFF


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_byte(n, STATE) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_byte(OFFSET + i, STATE) for i in range(LENGTH))
