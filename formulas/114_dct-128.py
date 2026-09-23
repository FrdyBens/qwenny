NAME = "DCT Fit T=128"
VERSION = "1.0.0"
DESCRIPTION = ("keep 128 cosine coefficients over a 4096-byte window; lossy approximation. Measures basis representation error per sample type.")
CATEGORY = "Signal"
TAGS = ["signal","lossy"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Truncated DCT-style basis fit: keep first T coefficients of a byte signal,
# reconstruct approximation. Tests signal-basis representation error (BER)
# on structured vs random data. Lossy by construction.
T = 128   # retained coefficients
N0 = 4096 # assumed period

def analyze(INPUT, PARAMETERS):
    import math
    xs = list(INPUT[:N0]) or [0]
    coefs = []
    for k in range(T):
        s = sum(x * math.cos(math.pi * k * (i + 0.5) / len(xs))
                for i, x in enumerate(xs))
        coefs.append(round(s / len(xs), 4))
    return {"coefs": coefs, "period": N0, "size": len(INPUT)}

def _val(n, STATE):
    import math
    c = STATE["coefs"]; P = STATE["period"]
    v = 0.0
    for k, a in enumerate(c):
        v += a * math.cos(math.pi * k * ((n % P) + 0.5) / P)
    return max(0, min(255, int(round(v))))

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * len(STATE["coefs"]))
    return bytes(_val(n, STATE) for n in range(SIZE))

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * len(STATE["coefs"]))
    return bytes(_val(OFFSET + i, STATE) for i in range(LENGTH))
