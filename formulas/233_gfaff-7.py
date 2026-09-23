NAME = "GF Affine Sub 7"
VERSION = "1.0.0"
DESCRIPTION = ("byte -> A*x+b over GF(2)^8 with random invertible matrix A (XOR of bit permutations): linear-algebra substitution family; bijection, true RA.")
CATEGORY = "Algebra"
TAGS = ["algebra","gf2","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


ROWS = [205, 99, 219, 128, 145, 44, 165, 161]
OFF = 99

def _apply(x):
    r = 0
    for i, rw in enumerate(ROWS):
        if (x >> i) & 1:
            r ^= rw
    return r ^ OFF

MAP = [_apply(i) for i in range(256)]
INV = [0]*256
for _i, _v in enumerate(MAP):
    INV[_v] = _i

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
