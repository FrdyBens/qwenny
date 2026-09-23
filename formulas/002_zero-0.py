NAME = "Zero"
VERSION = "1.0.0"
DESCRIPTION = ("Constant zero stream. Never matches real data; measures baseline BER.")
CATEGORY = "Baseline"
TAGS = ["baseline","index-only"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = False
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


K = 0

def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}

def _byte(n):
    return K % M

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_byte(n) for n in range(SIZE))

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_byte(OFFSET + i) for i in range(LENGTH))
