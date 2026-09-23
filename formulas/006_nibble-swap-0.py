NAME = "Nibble Swap"
VERSION = "1.0.0"
DESCRIPTION = ("Swap high/low nibbles. Byte-local bijection.")
CATEGORY = "Baseline"
TAGS = ["baseline","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


SW = [((i << 4) | (i >> 4)) & 255 for i in range(256)]

def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def _t(d):
    return bytes(SW[x] for x in d)

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    return _t(base64.b64decode(STATE["data_b64"]))[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    return _t(base64.b64decode(STATE["data_b64"])[OFFSET:OFFSET + LENGTH])
