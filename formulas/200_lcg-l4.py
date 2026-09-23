NAME = "LCG l4"
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


# LCG keystream: S'=(a*S+c)%2^64, byte(n)=low byte(S_n) XOR ciphertext copy.
# Classic recurrence; reads simulate => probe must flag NOT TRUE RA.
A = 15074714826142052245
C = 74565

def _step(s):
    return (A * s + C) & MASK

def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"lcgl4").digest()[:8], "big")
    s = s0
    enc = bytearray()
    for x in INPUT:
        s = _step(s)
        enc.append(x ^ (s & 255))
    return {"s0": s0, "size": len(INPUT),
            "enc_b64": __import__("base64").b64encode(bytes(enc)).decode()}

def _win(STATE, OFFSET, LENGTH):
    import base64
    e = base64.b64decode(STATE["enc_b64"])
    abc_formula.ops(OFFSET + LENGTH)
    s = STATE["s0"]
    for i in range(OFFSET + LENGTH):
        s = _step(s)
        if i >= OFFSET:
            yield e[i] ^ (s & 255)

def reconstruct(STATE, SIZE, PARAMETERS):
    return bytes(_win(STATE, 0, SIZE))

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    return bytes(_win(STATE, OFFSET, LENGTH))
