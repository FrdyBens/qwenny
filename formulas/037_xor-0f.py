NAME = "XOR 0x0F"
VERSION = "1.0.0"
DESCRIPTION = ("byte' = byte ^ k : additive group (Z2^8) action; bijection, true random access.")
CATEGORY = "Arithmetic"
TAGS = ["arithmetic","bijection","xor"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


K = 15


def _f(x):
    return x ^ K


def analyze(INPUT, PARAMETERS):
    # Pure law byte(n)=INPUT[n]^K. State holds only K: exactness on the
    # original is impossible unless K==0; BER measures the gap honestly.
    return {"k": K, "size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_f(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_f((OFFSET + i) & 0xFF) for i in range(LENGTH))
