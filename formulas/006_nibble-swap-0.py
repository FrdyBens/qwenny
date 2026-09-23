NAME = "Nibble Swap"
VERSION = "1.0.0"
DESCRIPTION = ("Swap high/low nibbles. Byte-local bijection.")
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


SW = [((i << 4) | (i >> 4)) & 255 for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(SW[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(SW[(OFFSET + i) & 0xFF] for i in range(LENGTH))
