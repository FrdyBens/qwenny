NAME = "Walsh Fit T=512"
VERSION = "1.0.0"
DESCRIPTION = ("retain 512 Hadamard correlations; lossy orthogonal-basis representation test.")
CATEGORY = "Signal"
TAGS = ["signal","lossy","walsh"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Walsh/Hadamard basis fit: keep first T +/-1 basis correlations over a
# windowed byte signal. Distinct from DCT: tests non-smooth orthogonal bases.
T = 512
N0 = 8192

def analyze(INPUT, PARAMETERS):
    xs = list(INPUT[:N0]) or [0]
    L = len(xs)
    coefs = []
    for k in range(min(T, L)):
        s = 0
        for i, x in enumerate(xs):
            # walsh sign = parity of dot(i, k) over bits
            p = bin(i & k).count("1") & 1
            s += x if p == 0 else -x
        coefs.append(round(s / L, 4))
    return {"coefs": coefs, "period": N0, "size": len(INPUT)}

def _val(n, STATE):
    c = STATE["coefs"]; P = STATE["period"]
    i = n % P
    v = 0.0
    for k, a in enumerate(c):
        v += a * (1 if bin(i & k).count("1") % 2 == 0 else -1)
    return max(0, min(255, int(round(v))))

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * len(STATE["coefs"]))
    return bytes(_val(n, STATE) for n in range(SIZE))

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * len(STATE["coefs"]))
    return bytes(_val(OFFSET + i, STATE) for i in range(LENGTH))
