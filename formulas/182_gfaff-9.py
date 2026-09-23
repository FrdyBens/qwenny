NAME = "GF Affine Sub 9"
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

ROWS = [44, 153, 40, 184, 232, 2, 24, 230]
OFF = 76


def _apply(x):
    r = 0
    for i, rw in enumerate(ROWS):
        if (x >> i) & 1:
            r ^= rw
    return r ^ OFF


MAP = [_apply(i) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    # pure linear-algebra law over GF(2)^8 applied to the index byte
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 8)
    return bytes(MAP[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 8)
    return bytes(MAP[(OFFSET + i) & 0xFF] for i in range(LENGTH))
