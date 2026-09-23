NAME = "Byteswap 16"
VERSION = "1.0.0"
DESCRIPTION = ("Swap adjacent byte pairs (endianness experiment).")
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


W = 2

def analyze(INPUT, PARAMETERS):
    return {"w": W, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def _t(d, w):
    out = bytearray(d)
    for i in range(0, len(out) - w + 1, w):
        out[i:i + w] = out[i:i + w][::-1]
    return bytes(out)

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    return _t(base64.b64decode(STATE["data_b64"]), STATE["w"])[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    w = STATE["w"]
    abc_formula.ops(LENGTH + w)
    blk = (OFFSET // w) * w
    d = base64.b64decode(STATE["data_b64"])
    return _t(d[blk:blk + ((OFFSET - blk) + LENGTH)], w)[(OFFSET - blk):][:LENGTH]
