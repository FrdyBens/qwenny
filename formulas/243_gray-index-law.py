NAME = "Gray Index Law"
VERSION = "1.0.0"
DESCRIPTION = ("byte(n)=gray(n%256): smooth bit-difference index law, position-only, true RA.")
CATEGORY = "BitOps"
TAGS = ["bitops","index-law"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Gray-code INDEX law: byte(n) = gray(n mod 256). Pure function of position,
# no data copy; measures how far a smooth bit-difference basis reaches.
def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def _g(x):
    return x ^ (x >> 1)


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_g(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_g((OFFSET + i) & 0xFF) for i in range(LENGTH))
