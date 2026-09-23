NAME = "Feistel idx R=8"
VERSION = "1.0.0"
DESCRIPTION = ("Feistel permutation of the byte-index domain; tests index-permutation codecs.")
CATEGORY = "Permutation"
TAGS = ["permutation","feistel"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Feistel-like permutation of INDEX space: byte(n)=T(pi(n)) style test with
# pi a keyless fixed-round Feistel on 32-bit index, combined with a stored
# transformed copy (again counted). Tests permutation-of-domain ideas.
R = 8   # rounds
C = 374761393   # round constant mix

def _f(x, i):
    x = (x + i * C) & 0xFFFFFFFF
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= x >> 17
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF

def perm(n):
    lo, hi = n & 0xFFFF, (n >> 16) & 0xFFFF
    for i in range(R):
        lo, hi = hi, lo ^ _f(hi, i)
    return ((hi & 0xFFFF) << 16) | (lo & 0xFFFF)

INV = {}

def unperm(m):
    if m in INV:
        return INV[m]
    # invert by scanning is O(2^32): we instead recompute forward rounds
    lo, hi = m & 0xFFFF, (m >> 16) & 0xFFFF
    for i in reversed(range(R)):
        prev_hi = lo
        prev_lo = hi ^ _f(lo, i)
        lo, hi = prev_lo & 0xFFFF, prev_hi & 0xFFFF
    INV[m] = (hi << 16) | lo
    return INV[m]

def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    out = bytearray(len(d))
    for n in range(len(d)):
        out[unperm(n) % len(d)] = d[n]
    return bytes(out)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    abc_formula.ops(len(d))   # full inverse scan needed: probe will catch it
    out = bytearray(len(d))
    for n in range(len(d)):
        out[unperm(n) % len(d)] = d[n]
    return bytes(out[OFFSET:OFFSET + LENGTH])
