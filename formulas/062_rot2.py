NAME = "Rotate 2"
VERSION = "1.0.0"
DESCRIPTION = ("circular rotate left by 2 bits.")
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

SH = 2


def _rot(x):
    return ((x << SH) | (x >> (8 - SH))) & 255


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_rot(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_rot((OFFSET + i) & 0xFF) for i in range(LENGTH))
