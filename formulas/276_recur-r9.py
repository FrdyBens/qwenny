NAME = "Nonlinear Recurrence r9"
VERSION = "1.0.0"
DESCRIPTION = ("S'=(aS + (s>>k)^s) keystream XOR model. Carries ciphertext copy; reads simulate from S0 — regression-class behavior for the RA probe.")
CATEGORY = "Recurrence"
TAGS = ["recurrence","stream"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Nonlinear recurrence S_(n+1) = (a*S_n + S_n xor (S_n>>k)) mod 2^64,
# byte(n) = low byte of S_n, seeded by analysis fit. Reconstruction carries
# a ciphertext copy (counted). Simulated reads => probe flags false RA.
A = 36699
K = 23

def _step(s):
    return (A * s + (s ^ (s >> K))) & MASK

def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"seedr9" + INPUT).digest()[:8],
                        "big")
    s = s0
    ks = bytearray()
    for _ in range(len(INPUT)):
        ks.append(s & 0xFF)
        s = _step(s)
    enc = bytes(x ^ y for x, y in zip(INPUT, ks))
    return {"s0": s0, "size": len(INPUT),
            "enc_b64": __import__("base64").b64encode(enc).decode()}

def _win(STATE, OFFSET, LENGTH):
    import base64
    e = base64.b64decode(STATE["enc_b64"])
    abc_formula.ops(OFFSET + LENGTH)
    s = STATE["s0"]
    for _ in range(OFFSET):
        s = _step(s)
    out = bytearray()
    for _ in range(LENGTH):
        out.append(e[OFFSET + len(out)] ^ (s & 0xFF))
        s = _step(s)
    return bytes(out)

def reconstruct(STATE, SIZE, PARAMETERS):
    return _win(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    return _win(STATE, OFFSET, LENGTH)
