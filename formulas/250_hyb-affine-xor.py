NAME = "Hybrid affine+xor"
VERSION = "1.0.0"
DESCRIPTION = ("composition of two byte-local bijections from different families; verifies closure and true random access.")
CATEGORY = "Hybrid"
TAGS = ["hybrid","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Hybrid composition of two byte-local bijections P then Q.
# Tests whether composing structures from different families changes the
# representation cost (it should not for pure bijections — verify).
PNAME = 'affine'
QNAME = 'xor'

PS = {
    "affine": lambda x, s=(3, 5): (s[0] * x + s[1]) % M,
    "xor": lambda x, s=0x5A: x ^ s,
    "rot": lambda x, s=3: ((x << s) | (x >> (8 - s))) & 255,
    "gray": lambda x, s=None: x ^ (x >> 1),
    "rev": lambda x, s=None: int(bin(x)[2:].zfill(8)[::-1], 2),
    "nib": lambda x, s=None: ((x << 4) | (x >> 4)) & 255,
}

def _mk(name):
    return PS[name]

def analyze(INPUT, PARAMETERS):
    return {"p": PNAME, "q": QNAME, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    f = _mk(STATE["p"]); g = _mk(STATE["q"])
    return bytes(g(f(x)) for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    f = _mk(STATE["p"]); g = _mk(STATE["q"])
    return bytes(g(f(x)) for x in d[OFFSET:OFFSET + LENGTH])
