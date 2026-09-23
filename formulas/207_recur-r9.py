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


# Nonlinear recurrence S_(n+1)=(A*S_n + S_n xor (S_n>>K)) mod 2^64 used as
# a DIRECT-INDEX law byte(n)=low8(S_n). No data copy: honest test of
# whether one seed can generate arbitrary content (it cannot; BER shows).
A = 36699
K = 23


def _step(s):
    return (A * s + (s ^ (s >> K))) & MASK


def _nth(seed, n):
    s = seed
    for _ in range(n):
        s = _step(s)
    return s


def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"recurr9" + INPUT).digest()[:8],
                        "big")
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
    abc_formula.ops(OFFSET + LENGTH)   # simulate from S0: probe will flag
    s = _nth(STATE["s0"], OFFSET)
    out = bytearray()
    for _ in range(LENGTH):
        out.append(s & 0xFF)
        s = _step(s)
    return bytes(out)
