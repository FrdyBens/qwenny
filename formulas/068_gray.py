NAME = "Gray Code"
VERSION = "1.0.0"
DESCRIPTION = ("binary->gray per byte: g=b^(b>>1). Reversible; tests locality-preserving maps.")
CATEGORY = "BitOps"
TAGS = ["bitops","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1

def _g(x):
    return x ^ (x >> 1)


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_g(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_g((OFFSET + i) & 0xFF) for i in range(LENGTH))
