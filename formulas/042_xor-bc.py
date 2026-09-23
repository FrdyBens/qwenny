NAME = "XOR 0xBC"
VERSION = "1.0.0"
DESCRIPTION = ("byte' = byte ^ k : additive group (Z2^8) action; bijection, true random access.")
CATEGORY = "Arithmetic"
TAGS = ["arithmetic","bijection","xor"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


K = 188

def analyze(INPUT, PARAMETERS):
    return {"k": K, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    k = STATE["k"]
    d = base64.b64decode(STATE["data_b64"])
    return bytes(x ^ k for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    k = STATE["k"]
    d = base64.b64decode(STATE["data_b64"])
    return bytes(x ^ k for x in d[OFFSET:OFFSET + LENGTH])
