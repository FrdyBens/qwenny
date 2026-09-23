NAME = "Half Interleave"
VERSION = "1.0.0"
DESCRIPTION = ("out[2i]=in[i], out[2i+1]=in[i+L/2]: global index permutation with O(1) inverse => true random access.")
CATEGORY = "BitOps"
TAGS = ["bitops","permutation"]
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
    return {"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def _src(n, L):
    half = L // 2
    if n % 2 == 0:
        return n // 2
    return half + n // 2

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes(d[_src(n, len(d))] for n in range(len(d)))[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes(d[_src(OFFSET + i, len(d))] for i in range(LENGTH))
