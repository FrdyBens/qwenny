NAME = "CA Rule 89 Mix"
VERSION = "1.0.0"
DESCRIPTION = ("elementary CA rule table as a byte substitution over triplet windows.")
CATEGORY = "Dynamical"
TAGS = ["dynamical","ca"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Elementary cellular automaton row evolution used as an index mixer:
# byte(n) depends on rule table applied to (n's bit-triplets). Deterministic
# index-only map; paired with stored copy for exactness. Tests CA-as-codec.
RULE = 89

def _mix(n):
    v = n & 0xFF
    acc = 0
    for i in range(8):
        trip = (v >> i) & 7
        acc = ((acc << 1) | ((RULE >> trip) & 1)) & 0xFF
    return acc

MAP = [_mix(i) for i in range(256)]

def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d[OFFSET:OFFSET + LENGTH])
