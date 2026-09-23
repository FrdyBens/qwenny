NAME = "GF Affine Index 5"
VERSION = "1.0.0"
DESCRIPTION = ("byte(n)=A*(n%256)+b over GF(2)^8, fixed published invertible A: linear-algebra index law family.")
CATEGORY = "Algebra"
TAGS = ["algebra","gf2","index-law"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# GF(2)^8 affine index law: byte(n) = A*(n mod 256) + b over GF(2), with a
# FIXED published invertible companion matrix A and constant b. Pure law.
ROWS = [126, 180, 49, 95, 68, 70, 36, 78]
OFF = 39


def _apply(x):
    r = 0
    for i, rw in enumerate(ROWS):
        if (x >> i) & 1:
            r ^= rw
    return r ^ OFF


MAP = [_apply(i) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 8)
    return bytes(MAP[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 8)
    return bytes(MAP[(OFFSET + i) & 0xFF] for i in range(LENGTH))
