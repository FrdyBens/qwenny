NAME = "MUL mod256 x27"
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


A = 27
B = 0

def analyze(INPUT, PARAMETERS):
    # Tests: can b[n] = A*INPUT[n]+B mod 256 represent data? (It cannot
    # shrink it — this measures how much structure real files give away.)
    inv = pow(A, -1, M) if A % 2 and A else None
    return {"a": A, "b": B, "inv": inv, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes((STATE["a"] * x + STATE["b"]) % M for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes((STATE["a"] * x + STATE["b"]) % M
                 for x in d[OFFSET:OFFSET + LENGTH])
