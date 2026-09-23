NAME = "Feistel idx R=4"
VERSION = "1.0.0"
DESCRIPTION = ("Feistel permutation of the byte-index domain; tests index-permutation codecs.")
CATEGORY = "Permutation"
TAGS = ["permutation","feistel"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Feistel permutation of the INDEX domain: byte(n) = pi(n) mod 256 with pi
# a keyless R-round Feistel on 32-bit indices. Pure law, no data copy.
# Inverse is O(R) per position => true random access candidate.
R = 4   # rounds
C = 3266489909   # round constant mix


def _f(x, i):
    x = (x + i * C) & 0xFFFFFFFF
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= x >> 17
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF


def perm(n):
    lo, hi = n & 0xFFFF, (n >> 16) & 0xFFFF
    for i in range(R):
        lo, hi = hi, lo ^ _f(hi, i)
    return ((hi & 0xFFFF) << 16) | (lo & 0xFFFF)


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * R)
    return bytes(perm(n) & 0xFF for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * R)
    return bytes(perm(OFFSET + i) & 0xFF for i in range(LENGTH))
