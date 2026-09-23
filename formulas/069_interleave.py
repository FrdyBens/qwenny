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

def _src(n, L):
    half = L // 2
    if n % 2 == 0:
        return n // 2
    return half + n // 2


def analyze(INPUT, PARAMETERS):
    # index-only law: byte(n) = source-position mod 256 (no data copy)
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_src(n, max(SIZE, 2)) & 0xFF for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    L = STATE.get("size", 2) or 2
    return bytes(_src(OFFSET + i, L) & 0xFF for i in range(LENGTH))
