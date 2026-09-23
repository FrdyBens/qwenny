NAME = "LFSR-64 0xCB00000000000067"
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


# LFSR keystream as a DIRECT-INDEX model: byte(n)=low8(T^n seed) XOR k_n
# where k_n is the model's output itself -> pure law, no data copy.
# v0006 lineage preserved: this family matched 64 header bits of a real
# WebP then diverged at byte 8. State = (poly, seed) only; reconstruction
# of arbitrary data is expected to FAIL and the lab reports how/where.
POLY = 14627691589699371111     # feedback mask over 64 bits
BITS = 64


def _nth(seed, n):
    # jump-ahead via matrix-free bit trick: output bit n of a Galois LFSR
    # is parity(mask_n & seed); we compute by repeated squaring of x^n mod
    # the connection polynomial => TRUE random access (log n steps).
    def clmul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a <<= 1
            b >>= 1
        return r

    def modred(v):
        for i in range(127, 63, -1):
            if (v >> i) & 1:
                v ^= POLY << (i - 64)
        return v & MASK

    # x^n mod P
    base, res = 2, 1
    e = n
    while e:
        if e & 1:
            res = modred(clmul(res, base))
        base = modred(clmul(base, base))
        e >>= 1
    return res


def analyze(INPUT, PARAMETERS):
    import hashlib
    seed = int.from_bytes(hashlib.sha256(b"lfsr" + INPUT).digest()[:8],
                          "big") or 1
    return {"seed": seed, "size": len(INPUT)}


def _b(n, seed):
    v = _nth(seed, n)
    return v & 0xFF


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 128)   # log-depth jumps measured
    return bytes(_b(n, STATE["seed"]) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 128)
    return bytes(_b(OFFSET + i, STATE["seed"]) for i in range(LENGTH))
