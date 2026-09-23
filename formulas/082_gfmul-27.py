NAME = "GF(2^8) MUL 27"
VERSION = "1.0.0"
DESCRIPTION = ("carry-less multiply by k in GF(2^8)/x^8+x^4+x^3+x+1. Bijection for k!=0.")
CATEGORY = "Algebra"
TAGS = ["algebra","finite-field","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Multiplication in GF(2^8) (AES polynomial) by fixed element K, applied to
# the BYTE AT THE POSITION treated as value n: byte(n)=gmul(n mod 256, K).
# Pure law; bijection when K!=0 so its inverse exists but there is no data
# in state to invert — this measures how well the law matches real bytes.
K = 27


def gmul(a, b):
    p = 0
    for i in range(8):
        if (b >> i) & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
    return p


def analyze(INPUT, PARAMETERS):
    return {"k": K, "size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 8)
    return bytes(gmul(n & 0xFF, K) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 8)
    return bytes(gmul((OFFSET + i) & 0xFF, K) for i in range(LENGTH))
