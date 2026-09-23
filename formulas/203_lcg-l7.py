NAME = "LCG l7"
VERSION = "1.0.0"
DESCRIPTION = ("linear congruential keystream XOR with stored ciphertext copy; recurrence-class control experiment.")
CATEGORY = "Recurrence"
TAGS = ["recurrence","lcg"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# LCG as direct-index law byte(n)=low8(S_n), S_(n+1)=(A*S_n+C) mod 2^64.
# State = seed only. Reconstruction of arbitrary data is not expected;
# this family measures the gap and whether jump-ahead gives true RA.
A = 25214903917
C = 11


def _step(s):
    return (A * s + C) & MASK


def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"lcgl7").digest()[:8], "big")
    return {"s0": s0, "size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    s = STATE["s0"]
    out = bytearray()
    for _ in range(SIZE):
        out.append(s & 0xFF)
        s = _step(s)
    return bytes(out)


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(OFFSET + LENGTH)   # simulate from S0: probe flags it
    s = STATE["s0"]
    for _ in range(OFFSET):
        s = _step(s)
    out = bytearray()
    for _ in range(LENGTH):
        out.append(s & 0xFF)
        s = _step(s)
    return bytes(out)
