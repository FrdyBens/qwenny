NAME = "Byteswap 32"
VERSION = "1.0.0"
DESCRIPTION = ("Reverse every 4-byte group.")
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


W = 4


def _pos(n):
    blk = (n // W) * W
    return blk + (W - 1 - (n % W))


def analyze(INPUT, PARAMETERS):
    return {"w": W, "size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_pos(n) & 0xFF for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_pos(OFFSET + i) & 0xFF for i in range(LENGTH))
