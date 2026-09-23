NAME = "MUL mod256 x21"
VERSION = "1.0.0"
DESCRIPTION = ("byte' = a*byte mod 256. Odd a bijective; even a loses information (test: how much?).")
CATEGORY = "Arithmetic"
TAGS = ["arithmetic"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


A = 21
B = 0


def _f(x):
    return (A * x + B) % M


def analyze(INPUT, PARAMETERS):
    # Pure law byte(n) = f(INPUT[n]) mod 256. State carries ONLY the law
    # parameters — no data copy. Therefore reconstruction of the ORIGINAL
    # is impossible unless f is identity; the runner measures exactly how
    # wrong it is (BER / first mismatch). This is the honest experiment.
    inv = pow(A, -1, M) if A % 2 and A else None
    return {"a": A, "b": B, "inv": inv, "size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_f(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_f((OFFSET + i) & 0xFF) for i in range(LENGTH))
