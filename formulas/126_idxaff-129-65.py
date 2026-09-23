NAME = "Index Affine a=129,b=65"
VERSION = "1.0.0"
DESCRIPTION = ("byte(n)=(a*n+b)%256 with params fitted from input head. Pure index law, no data stored: BER is the honest answer.")
CATEGORY = "DirectAccess"
TAGS = ["direct-access","index-law"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Pure index law: byte(n) = (a*n + b) mod 256. Zero data dependence except
# fitted a,b from input digest. Baseline for "F(parameters, n)" ambitions:
# shows how far two parameters get you on real data (answer: nowhere, and
# the matrix will prove it sample-by-sample).
FIT = 1

def analyze(INPUT, PARAMETERS):
    best = None
    # brute-force fit a,b over first 64 bytes (fast, honest, tiny state)
    head = INPUT[:8]
    for a in range(256):
        for b in range(0, 256, 1):
            err = sum(bin((a * i + b) % 256 ^ head[i]).count("1")
                      for i in range(min(8, len(head))))
            if best is None or err < best[0]:
                best = (err, a, b)
            if err == 0:
                break
        if best and best[0] == 0:
            break
    _, a, b = best or (999, 1, 0)
    return {"a": a, "b": b, "size": len(INPUT), "fit_head": FIT}

def _gen(STATE, lo, hi):
    a, b = STATE["a"], STATE["b"]
    return bytes((a * n + b) % M for n in range(lo, hi))

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return _gen(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return _gen(STATE, OFFSET, OFFSET + LENGTH)
