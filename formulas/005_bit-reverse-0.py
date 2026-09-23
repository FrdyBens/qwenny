NAME = "Bit Reverse"
VERSION = "1.0.0"
DESCRIPTION = ("Reverse the 8 bits of every byte. Byte-local bijection.")
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


REV = [int(bin(i)[2:].zfill(8)[::-1], 2) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(REV[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(REV[(OFFSET + i) & 0xFF] for i in range(LENGTH))
