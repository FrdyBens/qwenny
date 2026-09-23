NAME = "LFSR-64 #3"
VERSION = "1.0.0"
DESCRIPTION = ("64-bit Galois LFSR keystream XOR. v0006 lineage: matched 64 header bits of a WebP then diverged. Keeps ciphertext copy in state; probe should report simulated access.")
CATEGORY = "LFSR"
TAGS = ["lfsr","regression-v0006"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# LFSR keystream XOR model: state = (tap poly id, seed, ciphertext-copy).
# Reconstruction is exact ONLY because the ciphertext copy is carried —
# the lab counts it. Random access simulates from bit 0 => probe will say
# NOT TRUE RANDOM ACCESS. This preserves the v0006 lesson structurally.
POLY = 11745387828182253609     # feedback mask over 64 bits
BITS = 64

def _step(s):
    lsb = s & 1
    s >>= 1
    if lsb:
        s ^= POLY
    return s & MASK

def analyze(INPUT, PARAMETERS):
    import hashlib
    seed = int.from_bytes(hashlib.sha256(INPUT).digest()[:8], "big") or 1
    ks = []
    s = seed
    for _ in range(len(INPUT)):
        ks.append(s & 0xFF)
        s = _step(s)
        abc_formula.ops(1)
    enc = bytes(a ^ b for a, b in zip(INPUT, ks))
    return {"seed": seed, "size": len(INPUT),
            "enc_b64": __import__("base64").b64encode(enc).decode()}

def _stream(seed, n):
    s = seed
    for _ in range(n):
        yield s & 0xFF
        s = _step(s)

def _win(STATE, OFFSET, LENGTH):
    import base64
    e = base64.b64decode(STATE["enc_b64"])
    abc_formula.ops(OFFSET + LENGTH)   # simulated from start: measured!
    out = bytearray()
    s = STATE["seed"]
    for i in range(OFFSET):
        s = _step(s)
    for i in range(LENGTH):
        out.append(e[OFFSET + i] ^ (s & 0xFF))
        s = _step(s)
    return bytes(out)

def reconstruct(STATE, SIZE, PARAMETERS):
    return _win(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    return _win(STATE, OFFSET, LENGTH)
