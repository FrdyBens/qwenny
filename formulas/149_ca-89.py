NAME = "CA Rule 89 Mix"
VERSION = "1.0.0"
DESCRIPTION = ("elementary CA rule table as a byte substitution over triplet windows.")
CATEGORY = "Dynamical"
TAGS = ["dynamical","ca"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Elementary CA rule table as an index-only byte law: byte(n)=mix(n).
# Deterministic function of position; tests whether CA structure alone
# predicts arbitrary data (it should not — BER is the answer).
RULE = 89


def _mix(n):
    v = n & 0xFF
    acc = 0
    for i in range(8):
        trip = (v >> i) & 7
        acc = ((acc << 1) | ((RULE >> trip) & 1)) & 0xFF
    return acc


MAP = [_mix(i) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(MAP[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(MAP[(OFFSET + i) & 0xFF] for i in range(LENGTH))
