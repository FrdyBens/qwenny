NAME = "GF(2^8) MUL 17"
VERSION = "1.0.0"
DESCRIPTION = ("carry-less multiply by k in GF(2^8)/x^8+x^4+x^3+x+1. Bijection for k!=0.")
CATEGORY = "Algebra"
TAGS = ["algebra","finite-field","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Multiplication in GF(2^8) by a fixed element (carry-less, reduced by the
# AES polynomial). Byte-local bijection when k != 0: true random access.
K = 17

def gmul(a, b):
    p = 0
    for i in range(8):
        if (b >> i) & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
    return p

INVK = None
for _i in range(1, 256):
    if gmul(K, _i) == 1:
        INVK = _i
        break

def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    if STATE.get("inv"):
        return bytes(gmul(x, INVK) for x in d)[:SIZE]
    return bytes(gmul(x, K) for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH * 8)
    d = base64.b64decode(STATE["data_b64"])
    f = gmul
    if STATE.get("inv"):
        return bytes(f(x, INVK) for x in d[OFFSET:OFFSET + LENGTH])
    return bytes(f(x, K) for x in d[OFFSET:OFFSET + LENGTH])
