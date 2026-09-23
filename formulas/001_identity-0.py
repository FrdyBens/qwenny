NAME = "Identity"
VERSION = "1.0.0"
DESCRIPTION = ("BASELINE: stores input verbatim (base64 in state). Exact by construction; state ratio ~1.33. The honesty control.")
CATEGORY = "Baseline"
TAGS = ["baseline","stores-data"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


def analyze(INPUT, PARAMETERS):
    # BASELINE: deliberately stores the data. state_size exposes the cost.
    import base64
    return {"b64": base64.b64encode(INPUT).decode()}


def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    return base64.b64decode(STATE["b64"])[:SIZE]


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(1)
    d = base64.b64decode(STATE["b64"])
    return d[OFFSET:OFFSET + LENGTH]
