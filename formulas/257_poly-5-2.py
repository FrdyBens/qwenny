NAME = "Poly Index 5n^2+2n^3"
VERSION = "1.0.0"
DESCRIPTION = ("byte(n)=(c2*n^2+c3*n^3+n+b)%256 fitted offsets only; pure index law test.")
CATEGORY = "DirectAccess"
TAGS = ["direct-access","polynomial"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1

C2 = 5
C3 = 2
B = 7

def analyze(INPUT, PARAMETERS):
    # fit single additive offset b* minimizing error on first 8 bytes
    head = INPUT[:8]
    best = min(range(256), key=lambda bo: sum(
        bin(((C2*i*i + C3*i*i*i + i + B + bo) % M) ^ head[i]).count("1")
        for i in range(len(head))))
    return {"bo": best, "size": len(INPUT)}

def _gen(STATE, lo, hi):
    bo = STATE["bo"]
    return bytes((C2*n*n + C3*n*n*n + n + B + bo) % M for n in range(lo, hi))

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return _gen(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return _gen(STATE, OFFSET, OFFSET + LENGTH)
