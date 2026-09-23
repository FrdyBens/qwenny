NAME = "Hybrid affine+xor"
VERSION = "1.0.0"
DESCRIPTION = ("composition of two byte-local bijections from different families; verifies closure and true random access.")
CATEGORY = "Hybrid"
TAGS = ["hybrid","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Composition of two index-only byte laws P then Q (both from different
# families). Tests closure: composition of non-representing laws still
# represents nothing — and verifies the lab counts it that way.
PNAME = 'affine'
QNAME = 'xor'

PS = {
    "affine": lambda x: (3 * x + 5) % M,
    "xor": lambda x: x ^ 0x5A,
    "rot": lambda x: ((x << 3) | (x >> 5)) & 255,
    "gray": lambda x: x ^ (x >> 1),
    "rev": lambda x: int(bin(x)[2:].zfill(8)[::-1], 2),
    "nib": lambda x: ((x << 4) | (x >> 4)) & 255,
}


def analyze(INPUT, PARAMETERS):
    return {{"p": PNAME, "q": QNAME, "size": len(INPUT)}}


def _val(n):
    x = n & 0xFF
    return PS[QNAME](PS[PNAME](x))


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 2)
    return bytes(_val(n) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 2)
    return bytes(_val(OFFSET + i) for i in range(LENGTH))
