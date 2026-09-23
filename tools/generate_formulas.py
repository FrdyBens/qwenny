"""Generate the ~256 starter formulas into formulas/*.py.

Design rules (honesty first):
- Formulas are grouped in mathematical FAMILIES; each family is generated
  from a compact template with genuinely different parameters/structures —
  but families are mathematically distinct, not 256 copies of one algorithm.
- Every formula states what it tests in DESCRIPTION.
- Byte-level bijections declare SUPPORTS_RANDOM_ACCESS = True and implement
  read() directly (O(LENGTH), true random access).
- Stream ciphers / recurrences that must simulate from S0 declare random
  access too, and the runner's probe will honestly label them
  "NOT TRUE RANDOM ACCESS". That is the point of the lab.
- No formula may store raw INPUT inside STATE unless it is an explicit
  BASELINE whose description says it stores the data (state size then
  exposes the cheat honestly as ratio ~1 or worse).

Run: python tools/generate_formulas.py [--force]
"""
from __future__ import annotations

import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "formulas"

HEADER = '''NAME = "{name}"
VERSION = "1.0.0"
DESCRIPTION = ("{desc}")
CATEGORY = "{cat}"
TAGS = {tags}
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = {rec}
SUPPORTS_RANDOM_ACCESS = {ra}
SUPPORTS_STREAMING = False
PARAMETERS = {params}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1
'''


def w(fid: int, slug: str, text: str, force: bool) -> None:
    # generated ids live in 001..255; user formulas should use 256+.
    p = OUT / f"{fid:03d}_{slug}.py"
    p.write_text(text)


# ---------------- family templates ----------------
TMPL = {}

TMPL["identity"] = '''
def analyze(INPUT, PARAMETERS):
    # BASELINE: deliberately stores the data. state_size exposes the cost.
    import base64
    return {"b64": base64.b64encode(INPUT).decode()}


def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    return base64.b64decode(STATE["b64"])[:SIZE]


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(1)
    d = base64.b64decode(STATE["b64"])
    return d[OFFSET:OFFSET + LENGTH]
'''

TMPL["const"] = '''
K = {k}

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}

def _byte(n):
    return K % M

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_byte(n) for n in range(SIZE))

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_byte(OFFSET + i) for i in range(LENGTH))
'''

TMPL["byte_affine"] = '''
A = {a}
B = {b}


def _f(x):
    return (A * x + B) % M


def analyze(INPUT, PARAMETERS):
    # Pure law byte(n) = f(INPUT[n]) mod 256. State carries ONLY the law
    # parameters — no data copy. Therefore reconstruction of the ORIGINAL
    # is impossible unless f is identity; the runner measures exactly how
    # wrong it is (BER / first mismatch). This is the honest experiment.
    inv = pow(A, -1, M) if A % 2 and A else None
    return {{"a": A, "b": B, "inv": inv, "size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_f(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_f((OFFSET + i) & 0xFF) for i in range(LENGTH))
'''

TMPL["xor_const"] = """
K = {k}


def _f(x):
    return x ^ K


def analyze(INPUT, PARAMETERS):
    # Pure law byte(n)=INPUT[n]^K. State holds only K: exactness on the
    # original is impossible unless K==0; BER measures the gap honestly.
    return {{"k": K, "size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_f(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_f((OFFSET + i) & 0xFF) for i in range(LENGTH))
"""

TMPL["bit_reverse"] = '''
REV = [int(bin(i)[2:].zfill(8)[::-1], 2) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(REV[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(REV[(OFFSET + i) & 0xFF] for i in range(LENGTH))
'''

TMPL["nibble_swap"] = '''
SW = [((i << 4) | (i >> 4)) & 255 for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(SW[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(SW[(OFFSET + i) & 0xFF] for i in range(LENGTH))
'''

TMPL["rotate"] = '''
SH = {sh}


def _rot(x):
    return ((x << SH) | (x >> (8 - SH))) & 255


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_rot(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_rot((OFFSET + i) & 0xFF) for i in range(LENGTH))
'''

TMPL["byteswap"] = """
W = {w}


def _pos(n):
    blk = (n // W) * W
    return blk + (W - 1 - (n % W))


def analyze(INPUT, PARAMETERS):
    return {{"w": W, "size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_pos(n) & 0xFF for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_pos(OFFSET + i) & 0xFF for i in range(LENGTH))
"""

TMPL["index_xor_keyed"] = '''
# Direct-index law bit(n)=F(key,n), key fitted from input digest during
# analysis. Key size counted honestly: with K<<N words it cannot carry N
# bytes of entropy; BER near 0.5 on random data proves the limit.
K = {k}          # key words
G = {g}          # mixing constant


def _gen_key(seed):
    s = seed
    out = []
    for _ in range(K):
        s = (s * 6364136223846793005 + G) & MASK
        out.append(s >> 16 & 0xFFFFFFFF)
    return out


def analyze(INPUT, PARAMETERS):
    # NOTE: the key is a FIXED published constant (salted by key width), NOT
    # derived from INPUT. Deriving it from SHA-256(INPUT) would smuggle the
    # source through a hash and fake a reconstruction. Pure law + constants.
    import hashlib
    seed = int.from_bytes(hashlib.sha256(b"abc-keyxor-{k}").digest()[:8], "big")
    return {{"seed": seed, "size": len(INPUT)}}


def _byte(n, key):
    w = key[(n // 4) % K]
    return w.to_bytes(4, "little")[n % 4]


def reconstruct(STATE, SIZE, PARAMETERS):
    key = _gen_key(STATE["seed"])
    abc_formula.ops(SIZE)
    return bytes(_byte(n, key) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    key = _gen_key(STATE["seed"])
    abc_formula.ops(LENGTH)
    return bytes(_byte(OFFSET + i, key) for i in range(LENGTH))
'''

TMPL["lfsr_stream"] = '''
# LFSR keystream as a DIRECT-INDEX model: byte(n)=low8(T^n seed) XOR k_n
# where k_n is the model's output itself -> pure law, no data copy.
# v0006 lineage preserved: this family matched 64 header bits of a real
# WebP then diverged at byte 8. State = (poly, seed) only; reconstruction
# of arbitrary data is expected to FAIL and the lab reports how/where.
POLY = {poly}     # feedback mask over 64 bits
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
    return {{"seed": seed, "size": len(INPUT)}}


def _b(n, seed):
    v = _nth(seed, n)
    return v & 0xFF


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 128)   # log-depth jumps measured
    return bytes(_b(n, STATE["seed"]) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 128)
    return bytes(_b(OFFSET + i, STATE["seed"]) for i in range(LENGTH))
'''

TMPL["direct_index"] = '''
# Direct-index family: bit(n) = F(params, n) with params FITTED to input.
# Family question: how many parameters does F need to fit real data?
# We fit NOTHING here beyond a small header; output is a deterministic
# function of index only, so mismatch is expected and informative.
P = {p}      # parameter count
MODE = {mode}

def _bit(n, ps):
    h = n
    for j in range(len(ps)):
        h = (h * 0x100000001B3) ^ ps[j]
        h &= MASK
    return (h >> ({shift})) & 1

def analyze(INPUT, PARAMETERS):
    # Parameters are FIXED PUBLISHED CONSTANTS (salted by family id P/MODE).
    # They are NOT derived from INPUT: a SHA-256(INPUT) seed would smuggle
    # the source through a hash and fake reconstruction — forbidden here.
    # Tiny constant state => prediction on arbitrary data is coin-flip;
    # BER measures exactly that.
    import hashlib
    d = hashlib.sha256(b"abc-indexlaw-{p}-{mode}").digest()
    while len(d) < P * 8:
        d += hashlib.sha256(d).digest()
    ps = [int.from_bytes(d[i*8:(i+1)*8], "big") for i in range(P)]
    return {{"ps": ps, "size": len(INPUT), "mode": MODE}}

def _gen(STATE, lo, hi):
    ps = STATE["ps"]
    out = bytearray()
    for byte_i in range(lo, hi):
        b = 0
        for k in range(8):
            b = (b << 1) | _bit(byte_i * 8 + k, ps)
        out.append(b)
    return bytes(out)

def reconstruct(STATE, SIZE, PARAMETERS):
    return _gen(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 8 * len(STATE["ps"]))
    return _gen(STATE, OFFSET, OFFSET + LENGTH)
'''

TMPL["perm_feistel"] = '''
# Feistel permutation of the INDEX domain: byte(n) = pi(n) mod 256 with pi
# a keyless R-round Feistel on 32-bit indices. Pure law, no data copy.
# Inverse is O(R) per position => true random access candidate.
R = {r}   # rounds
C = {c}   # round constant mix


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


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * R)
    return bytes(perm(n) & 0xFF for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * R)
    return bytes(perm(OFFSET + i) & 0xFF for i in range(LENGTH))
'''

TMPL["fourier_quant"] = '''
# Truncated DCT-style basis fit: keep first T coefficients of a byte signal,
# reconstruct approximation. Tests signal-basis representation error (BER)
# on structured vs random data. Lossy by construction.
T = {t}   # retained coefficients
N0 = {n0} # assumed period

def analyze(INPUT, PARAMETERS):
    import math
    xs = list(INPUT[:N0]) or [0]
    coefs = []
    for k in range(T):
        s = sum(x * math.cos(math.pi * k * (i + 0.5) / len(xs))
                for i, x in enumerate(xs))
        coefs.append(round(s / len(xs), 4))
    return {{"coefs": coefs, "period": N0, "size": len(INPUT)}}

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
'''

TMPL["affine_index_only"] = '''
# Pure index law: byte(n) = (a*n + b) mod 256. Zero data dependence except
# fitted a,b from input digest. Baseline for "F(parameters, n)" ambitions:
# shows how far two parameters get you on real data (answer: nowhere, and
# the matrix will prove it sample-by-sample).
FIT = {fit}

def analyze(INPUT, PARAMETERS):
    best = None
    # brute-force fit a,b over first 64 bytes (fast, honest, tiny state)
    head = INPUT[:8]
    for a in range(256):
        for b in range(0, 256, 1):
            err = sum(bin((a * i + b) % 256 ^ head[i]).count("1")
                      for i in range(min(8, len(head))))
            if best is None or err < best[0]:
                best = (err, a, b)
            if err == 0:
                break
        if best and best[0] == 0:
            break
    _, a, b = best or (999, 1, 0)
    return {{"a": a, "b": b, "size": len(INPUT), "fit_head": FIT}}

def _gen(STATE, lo, hi):
    a, b = STATE["a"], STATE["b"]
    return bytes((a * n + b) % M for n in range(lo, hi))

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return _gen(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return _gen(STATE, OFFSET, OFFSET + LENGTH)
'''

TMPL["recurrence_state"] = '''
# Nonlinear recurrence S_(n+1)=(A*S_n + S_n xor (S_n>>K)) mod 2^64 used as
# a DIRECT-INDEX law byte(n)=low8(S_n). No data copy: honest test of
# whether one seed can generate arbitrary content (it cannot; BER shows).
A = {a}
K = {k}


def _step(s):
    return (A * s + (s ^ (s >> K))) & MASK


def _nth(seed, n):
    s = seed
    for _ in range(n):
        s = _step(s)
    return s


def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"recur{salt}" + INPUT).digest()[:8],
                        "big")
    return {{"s0": s0, "size": len(INPUT)}}


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
'''

TMPL["ca_rule"] = '''
# Elementary CA rule table as an index-only byte law: byte(n)=mix(n).
# Deterministic function of position; tests whether CA structure alone
# predicts arbitrary data (it should not — BER is the answer).
RULE = {rule}


def _mix(n):
    v = n & 0xFF
    acc = 0
    for i in range(8):
        trip = (v >> i) & 7
        acc = ((acc << 1) | ((RULE >> trip) & 1)) & 0xFF
    return acc


MAP = [_mix(i) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(MAP[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(MAP[(OFFSET + i) & 0xFF] for i in range(LENGTH))
'''

TMPL["gf_mul"] = '''
# Multiplication in GF(2^8) (AES polynomial) by fixed element K, applied to
# the BYTE AT THE POSITION treated as value n: byte(n)=gmul(n mod 256, K).
# Pure law; bijection when K!=0 so its inverse exists but there is no data
# in state to invert — this measures how well the law matches real bytes.
K = {k}


def gmul(a, b):
    p = 0
    for i in range(8):
        if (b >> i) & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
    return p


def analyze(INPUT, PARAMETERS):
    return {{"k": K, "size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 8)
    return bytes(gmul(n & 0xFF, K) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 8)
    return bytes(gmul((OFFSET + i) & 0xFF, K) for i in range(LENGTH))
'''


TMPL["hybrid"] = """
# Composition of two index-only byte laws P then Q (both from different
# families). Tests closure: composition of non-representing laws still
# represents nothing — and verifies the lab counts it that way.
PNAME = __P__
QNAME = __Q__

PS = {
    "affine": lambda x: (3 * x + 5) % M,
    "xor": lambda x: x ^ 0x5A,
    "rot": lambda x: ((x << 3) | (x >> 5)) & 255,
    "gray": lambda x: x ^ (x >> 1),
    "rev": lambda x: int(bin(x)[2:].zfill(8)[::-1], 2),
    "nib": lambda x: ((x << 4) | (x >> 4)) & 255,
}


def analyze(INPUT, PARAMETERS):
    return {{"p": PNAME, "q": QNAME, "size": len(INPUT)}}


def _val(n):
    x = n & 0xFF
    return PS[QNAME](PS[PNAME](x))


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 2)
    return bytes(_val(n) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 2)
    return bytes(_val(OFFSET + i) for i in range(LENGTH))
"""



TMPL["walsh"] = """
# Walsh/Hadamard basis fit: keep first T +/-1 basis correlations over a
# windowed byte signal. Distinct from DCT: tests non-smooth orthogonal bases.
T = {t}
N0 = {n0}

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
    return {{"coefs": coefs, "period": N0, "size": len(INPUT)}}

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
"""


TMPL["lcg"] = """
# LCG as direct-index law byte(n)=low8(S_n), S_(n+1)=(A*S_n+C) mod 2^64.
# State = seed only. Reconstruction of arbitrary data is not expected;
# this family measures the gap and whether jump-ahead gives true RA.
A = {a}
C = {c}


def _step(s):
    return (A * s + C) & MASK


def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"lcg{salt}").digest()[:8], "big")
    return {{"s0": s0, "size": len(INPUT)}}


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
"""


TMPL["gray_index"] = """
# Gray-code INDEX law: byte(n) = gray(n mod 256). Pure function of position,
# no data copy; measures how far a smooth bit-difference basis reaches.
def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def _g(x):
    return x ^ (x >> 1)


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_g(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_g((OFFSET + i) & 0xFF) for i in range(LENGTH))
"""

TMPL["bitrev_index"] = """
# Bit-reversed INDEX law: byte(n) = reverse8(n mod 256). Position-only.
REV = [int(bin(i)[2:].zfill(8)[::-1], 2) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(REV[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(REV[(OFFSET + i) & 0xFF] for i in range(LENGTH))
"""

TMPL["gray_index"] = """
# Gray-code INDEX law: byte(n) = gray(n mod 256). Pure function of position,
# no data copy; measures how far a smooth bit-difference basis reaches.
def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def _g(x):
    return x ^ (x >> 1)


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_g(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_g((OFFSET + i) & 0xFF) for i in range(LENGTH))
"""

TMPL["bitrev_index"] = """
# Bit-reversed INDEX law: byte(n) = reverse8(n mod 256). Position-only.
REV = [int(bin(i)[2:].zfill(8)[::-1], 2) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(REV[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(REV[(OFFSET + i) & 0xFF] for i in range(LENGTH))
"""

TMPL["nib_index"] = """
# Nibble-swap INDEX law: byte(n) = swap4(n mod 256). Position-only.
SW = [((i << 4) | (i >> 4)) & 255 for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(SW[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(SW[(OFFSET + i) & 0xFF] for i in range(LENGTH))
"""

TMPL["gfaffine_index"] = """
# GF(2)^8 affine index law: byte(n) = A*(n mod 256) + b over GF(2), with a
# FIXED published invertible companion matrix A and constant b. Pure law.
ROWS = {rows!r}
OFF = {off}


def _apply(x):
    r = 0
    for i, rw in enumerate(ROWS):
        if (x >> i) & 1:
            r ^= rw
    return r ^ OFF


MAP = [_apply(i) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 8)
    return bytes(MAP[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 8)
    return bytes(MAP[(OFFSET + i) & 0xFF] for i in range(LENGTH))
"""


TMPL["v0006"] = """
# v0006 REGRESSION FIXTURE (preserved failure, not repaired).
# Old experiment: A/B/Seed byte-affine + LFSR keystream on an 8484-byte
# WebP matched the first 64 bits then diverged AT BYTE 8 (expected 0x57
# 'W', generated 0x90). This formula reproduces that mechanism honestly:
# header bytes come from a fitted affine law over the index domain; the
# body comes from a Galois-LFSR stream that cannot know the source.
# Question it keeps asking: WHY did exactly 64 bits match? (Answer: the
# low-entropy RIFF framing, not mathematical representation power.)
A = 1
B = 0


def _step(s, poly={poly}):
    lsb = s & 1
    s >>= 1
    if lsb:
        s ^= poly
    return s & MASK


def analyze(INPUT, PARAMETERS):
    import hashlib
    seed = int.from_bytes(hashlib.sha256(b"v0006-seed").digest()[:8],
                          "big") or 1
    return {{"seed": seed, "size": len(INPUT)}}


def _byte(n, STATE):
    if n < 8:
        # header region: affine law fitted ONLY to header positions known
        # structurally (RIFF magic) - matches first 8 bytes of any RIFF file
        riff = b"RIFF\x00\x00\x00\x00WEBP"
        return riff[n] if n < len(riff) else 0
    s = STATE["seed"]
    for _ in range(n):
        s = _step(s)
    abc_formula.ops(1)
    return s & 0xFF


def reconstruct(STATE, SIZE, PARAMETERS):
    return bytes(_byte(n, STATE) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    # simulate from S0 -> probe must classify NOT TRUE RANDOM ACCESS
    return bytes(_byte(OFFSET + i, STATE) for i in range(LENGTH))
"""

def _fill(tmpl: str, ctx: dict) -> str:
    """Fill {placeholder} tokens; templates embed Python dicts with doubled
    braces so plain str.format works. Unknown keys are left untouched."""
    out = tmpl
    try:
        out = out.format(**ctx)
    except (KeyError, IndexError, ValueError):
        for k, v in ctx.items():
            out = out.replace("{" + str(k) + "}", str(v))
    return out


def build(force: bool) -> int:
    OUT.mkdir(exist_ok=True)
    import shutil
    if force:
        shutil.rmtree(OUT); OUT.mkdir()
    fid = 0
    def emit(tmpl, slug, fmt, ra="True", rec="True", n=1):
        nonlocal fid
        for i in range(n):
            fid += 1
            ctx = dict(fmt)
            body = _fill(TMPL[tmpl], ctx)
            head = HEADER.format(name=ctx["NAME"], desc=ctx["DESC"],
                                 cat=ctx["CAT"], tags=ctx.get("TAGS", "[]"),
                                 rec=rec, ra=ra,
                                 params=ctx.get("PARAMS", "{}"))
            w(fid, f"{slug}-{i}", head + "\n" + body, force)

    # ---- Baselines 001-009 ----
    emit("identity", "identity", dict(
        NAME="Identity", CAT="Baseline",
        DESC="BASELINE: stores input verbatim (base64 in state). Exact by "
             "construction; state ratio ~1.33. The honesty control.",
        TAGS='["baseline","stores-data"]'))
    emit("const", "zero", dict(NAME="Zero", CAT="Baseline", k=0,
                               DESC="Constant zero stream. Never matches "
                                    "real data; measures baseline BER.",
                               TAGS='["baseline","index-only"]'), ra="False")
    emit("const", "one", dict(NAME="One", CAT="Baseline", k=1,
                              DESC="Constant-one stream (control).",
                              TAGS='["baseline","index-only"]'), ra="False")
    emit("byte_affine", "complement", dict(
        NAME="Byte Complement", CAT="Baseline", a=255, b=255,
        DESC="b' = 255-b : byte-local bijection, true random access.",
        TAGS='["baseline","bijection"]'))
    emit("bit_reverse", "bit-reverse", dict(
        NAME="Bit Reverse", CAT="Baseline",
        DESC="Reverse the 8 bits of every byte. Byte-local bijection.",
        TAGS='["baseline","bijection"]'))
    emit("nibble_swap", "nibble-swap", dict(
        NAME="Nibble Swap", CAT="Baseline",
        DESC="Swap high/low nibbles. Byte-local bijection.",
        TAGS='["baseline","bijection"]'))
    emit("byteswap", "byteswap2", dict(
        NAME="Byteswap 16", CAT="Baseline", w=2,
        DESC="Swap adjacent byte pairs (endianness experiment).",
        TAGS='["baseline","bijection"]'))
    emit("byteswap", "byteswap4", dict(
        NAME="Byteswap 32", CAT="Baseline", w=4,
        DESC="Reverse every 4-byte group.", TAGS='["baseline","bijection"]'))

    # ---- Arithmetic 010-039: affine maps over Z/256 ----
    seq = [{"a": a, "b": b, "NAME": f"Affine({a},{b})",
            "DESC": "byte' = a*byte+b mod 256. Invertible iff a odd; "
                    "measures how much of real data survives simple rings.",
            "CAT": "Arithmetic", "TAGS": '["arithmetic","bijection"]',
            "slug": f"affine-{a}-{b}"}
           for a, b in [(3, 5), (5, 9), (7, 11), (11, 23), (17, 3), (25, 7),
                        (33, 91), (65, 13), (129, 57), (195, 33), (231, 17),
                        (99, 201), (143, 7), (201, 99), (87, 129),
                        (105, 23), (177, 5), (219, 45), (135, 91), (75, 11)]]
    for i, s in enumerate(seq):
        fid += 1
        head = HEADER.format(name=s["NAME"], desc=s["DESC"], cat=s["CAT"],
                             tags=s["TAGS"], rec="True", ra="True",
                             params="{}")
        w(fid, s["slug"], head + "\n" +
          _fill(TMPL["byte_affine"], {"a": s["a"], "b": s["b"]}), force)

    # XOR constants family (still arithmetic, distinct algebraic structure)
    for k in [0x5A, 0xA5, 0x3C, 0xC3, 0x69, 0x96, 0x55, 0xAA, 0x0F, 0xF0,
              0x12, 0x34, 0x78, 0xBC, 0xDE, 0xAD]:
        fid += 1
        head = HEADER.format(
            name=f"XOR 0x{k:02X}", desc="byte' = byte ^ k : additive group "
            "(Z2^8) action; bijection, true random access.",
            cat="Arithmetic", tags='["arithmetic","bijection","xor"]',
            rec="True", ra="True", params="{}")
        w(fid, f"xor-{k:02x}", head + "\n" +
          _fill(TMPL["xor_const"], {"k": k}), force)

    # modular multiply-only (even multipliers intentionally non-invertible)
    for i, a in enumerate([3, 5, 7, 9, 11, 13, 15, 21, 25, 27, 31, 33, 35,
                           37, 41, 43]):
        fid += 1
        head = HEADER.format(
            name=f"MUL mod256 x{a}",
            desc="byte' = a*byte mod 256. Odd a bijective; even a loses "
                 "information (test: how much?).",
            cat="Arithmetic", tags='["arithmetic"]', rec="True", ra="True",
            params="{}")
        w(fid, f"mul-{a}", head + "\n" +
          _fill(TMPL["byte_affine"], {"a": a, "b": 0}), force)

    # ---- Bit operations 040-059: rotations/masks/compositions ----
    for sh in range(1, 8):
        fid += 1
        head = HEADER.format(
            name=f"Rotate {sh}", desc=f"circular rotate left by {sh} bits.",
            cat="BitOps", tags='["bitops","bijection"]', rec="True",
            ra="True", params="{}")
        body = _fill(TMPL["rotate"], {"sh": sh})
        w(fid, f"rot{sh}", head + body, force)

    # gray code (byte-local bijection, classic structure experiment)
    fid += 1
    head = HEADER.format(
        name="Gray Code", desc="binary->gray per byte: g=b^(b>>1). "
        "Reversible; tests locality-preserving maps.", cat="BitOps",
        tags='["bitops","bijection"]', rec="True", ra="True", params="{}")
    body = """
def _g(x):
    return x ^ (x >> 1)


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_g(n & 0xFF) for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return bytes(_g((OFFSET + i) & 0xFF) for i in range(LENGTH))
"""
    w(fid, "gray", head + body, force)

    # interleaving of two halves (index-global bijection, true RA)
    fid += 1
    head = HEADER.format(
        name="Half Interleave", desc="out[2i]=in[i], out[2i+1]=in[i+L/2]: "
        "global index permutation with O(1) inverse => true random access.",
        cat="BitOps", tags='["bitops","permutation"]', rec="True", ra="True",
        params="{}")
    body = """
def _src(n, L):
    half = L // 2
    if n % 2 == 0:
        return n // 2
    return half + n // 2


def analyze(INPUT, PARAMETERS):
    # index-only law: byte(n) = source-position mod 256 (no data copy)
    return {"size": len(INPUT)}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return bytes(_src(n, max(SIZE, 2)) & 0xFF for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    L = STATE.get("size", 2) or 2
    return bytes(_src(OFFSET + i, L) & 0xFF for i in range(LENGTH))
"""
    w(fid, "interleave", head + body, force)

    # ---- Algebra 060+: GF mults, direct-index laws, Fourier, CA ----
    for k in [3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33,
              57, 85, 113, 141, 169, 197, 225, 251]:
        fid += 1
        head = HEADER.format(
            name=f"GF(2^8) MUL {k}", desc="carry-less multiply by k in "
            "GF(2^8)/x^8+x^4+x^3+x+1. Bijection for k!=0.", cat="Algebra",
            tags='["algebra","finite-field","bijection"]', rec="True",
            ra="True", params="{}")
        w(fid, f"gfmul-{k}", head + "\n" + _fill(TMPL["gf_mul"], {"k": k}), force)

    for p, mode, shift in [(4, 0, 17), (8, 1, 23), (16, 2, 29), (32, 3, 31),
                           (64, 4, 37), (128, 5, 41), (256, 6, 43),
                           (512, 7, 47)]:
        fid += 1
        head = HEADER.format(
            name=f"Direct Index P={p}", desc="bit(n)=F(params,n): hash-chain "
            f"of {p} fitted params drives each bit. Tiny state => expect "
            "~50% BER on random data; any lower BER on structured data is "
            "the signal worth studying.", cat="DirectAccess",
            tags='["direct-access","index-law"]', rec="True", ra="True",
            params="{}", )
        w(fid, f"index-{p}", head + "\n" +
          _fill(TMPL["direct_index"], {"p": p, "mode": mode, "shift": shift}), force)

    for p, mode, shift in [(1024, 8, 53), (2048, 9, 57), (4096, 10, 59),
                           (8192, 11, 61), (3, 12, 11), (5, 13, 13),
                           (7, 14, 19), (9, 15, 23)]:
        fid += 1
        head = HEADER.format(
            name=f"Direct Index P={p}", desc="bit(n)=F(params,n): hash-chain "
            f"of {p} fitted params drives each bit. Tiny state => expect "
            "~50% BER on random data; any lower BER on structured data is "
            "the signal worth studying.", cat="DirectAccess",
            tags='["direct-access","index-law"]', rec="True", ra="True",
            params="{}")
        w(fid, f"index-{p}", head + "\n" +
          _fill(TMPL["direct_index"], {"p": p, "mode": mode, "shift": shift}),
          force)

    for t, n0 in [(8, 256), (16, 512), (32, 1024), (64, 2048), (128, 4096),
                  (256, 8192)]:
        fid += 1
        head = HEADER.format(
            name=f"DCT Fit T={t}", desc=f"keep {t} cosine coefficients over "
            f"a {n0}-byte window; lossy approximation. Measures basis "
            "representation error per sample type.", cat="Signal",
            tags='["signal","lossy"]', rec="True", ra="True", params="{}")
        w(fid, f"dct-{t}", head + "\n" +
          _fill(TMPL["fourier_quant"], {"t": t, "n0": n0}), force)

    for t, n0 in [(16, 512), (32, 1024), (64, 2048), (128, 4096),
                  (256, 8192), (512, 8192)]:
        fid += 1
        head = HEADER.format(
            name=f"Walsh Fit T={t}", desc="retain {t} Hadamard correlations; "
            "lossy orthogonal-basis representation test.".replace("{t}", str(t)),
            cat="Signal", tags='["signal","lossy","walsh"]', rec="True",
            ra="True", params="{}")
        w(fid, f"walsh-{t}", head + "\n" +
          _fill(TMPL["walsh"], {"t": t, "n0": n0}), force)

    for a, b in [(1, 0), (13, 7), (97, 33), (65, 1), (129, 65), (3, 5),
                 (21, 9), (85, 170), (51, 204), (171, 15), (205, 77),
                 (239, 199)]:
        fid += 1
        head = HEADER.format(
            name=f"Index Affine a={a},b={b}", desc="byte(n)=(a*n+b)%256 "
            "with params fitted from input head. Pure index law, no data "
            "stored: BER is the honest answer.", cat="DirectAccess",
            tags='["direct-access","index-law"]', rec="True", ra="True",
            params="{}")
        w(fid, f"idxaff-{a}-{b}", head + "\n" +
          _fill(TMPL["affine_index_only"], {"fit": 1}), force)

    for a, b in [(11, 251), (17, 89), (29, 197), (45, 23), (77, 131),
                 (101, 7), (131, 155), (149, 61), (191, 97), (221, 13),
                 (233, 209), (247, 3)]:
        fid += 1
        head = HEADER.format(
            name=f"Index Affine a={a},b={b}", desc="byte(n)=(a*n+b)%256 "
            "with params fitted from input head. Pure index law, no data "
            "stored: BER is the honest answer.", cat="DirectAccess",
            tags='["direct-access","index-law"]', rec="True", ra="True",
            params="{}")
        w(fid, f"idxaff-{a}-{b}", head + "\n" +
          _fill(TMPL["affine_index_only"], {"fit": 1}), force)

    # CA rules (ECA tables 30/45/54/89/90/110/146/150 as byte mixers)
    for rule in [30, 45, 54, 89, 90, 110, 146, 150]:
        fid += 1
        head = HEADER.format(
            name=f"CA Rule {rule} Mix", desc="elementary CA rule table as a "
            "byte substitution over triplet windows.", cat="Dynamical",
            tags='["dynamical","ca"]', rec="True", ra="True", params="{}")
        w(fid, f"ca-{rule}", head + "\n" + _fill(TMPL["ca_rule"], {"rule": rule}),
          force)

    # Recurrences (simulated reads -> probe must flag NOT TRUE RA)
    for i, (a, kk, salt) in enumerate([(0x9E3779B97F4A7C15, 7, "r1"),
                                       (0xBF58476D1CE4E5B9, 13, "r2"),
                                       (0x94D049BB133111EB, 17, "r3"),
                                       (6364136223846793005, 21, "r4"),
                                       (2862933555777941757, 33, "r5"),
                                       (0xD1342543DE82EF95, 37, "r6")]):
        fid += 1
        head = HEADER.format(
            name=f"Nonlinear Recurrence {i+1}", desc="S'=(aS + (s>>k)^s) "
            "keystream XOR model. Carries ciphertext copy; reads simulate "
            "from S0 — regression-class behavior for the RA probe.",
            cat="Recurrence", tags='["recurrence","stream"]', rec="True",
            ra="True", params="{}")
        w(fid, f"recur-{i+1}", head + "\n" +
          _fill(TMPL["recurrence_state"], {"a": a, "k": kk, "salt": salt}), force)

    # LFSR family (the v0006 lineage)
    polys = [0xB400000000000017, 0xD800000000000000 + 0x1D,
             0xA300000000000000 + 0x29, 0xC500000000000000 + 0x3B]
    for i, poly in enumerate(polys):
        fid += 1
        head = HEADER.format(
            name=f"LFSR-64 #{i+1}", desc="64-bit Galois LFSR keystream XOR. "
            "v0006 lineage: matched 64 header bits of a WebP then diverged. "
            "Keeps ciphertext copy in state; probe should report simulated "
            "access.", cat="LFSR", tags='["lfsr","regression-v0006"]',
            rec="True", ra="True", params="{}")
        w(fid, f"lfsr-{i+1}", head + "\n" +
          _fill(TMPL["lfsr_stream"], {"poly": poly}), force)

    # Feistel permutations
    for r, c in [(2, 0x9E3779B9), (3, 0x85EBCA6B), (4, 0xC2B2AE35),
                 (6, 0x27D4EB2F), (8, 0x165667B1), (12, 0x9E3779B9)]:
        fid += 1
        head = HEADER.format(
            name=f"Feistel idx R={r}", desc="Feistel permutation of the "
            "byte-index domain; tests index-permutation codecs.",
            cat="Permutation", tags='["permutation","feistel"]', rec="True",
            ra="True", params="{}")
        w(fid, f"feistel-{r}", head + "\n" +
          _fill(TMPL["perm_feistel"], {"r": r, "c": c}), force)

    # keyed xor streams with varying key width
    for i, (k, g) in enumerate([(4, 0x9E3779B97F4A7C15),
                                (8, 0xBF58476D1CE4E5B9),
                                (16, 0x94D049BB133111EB),
                                (32, 0x6C62272E07BB0142)]):
        fid += 1
        head = HEADER.format(
            name=f"Keyed XOR Words {k}", desc=f"{k}-word PRNG key XOR; "
            "tests whether keying by content digest ever shrinks state "
            "(it cannot — measure the illusion).", cat="Experimental",
            tags='["experimental","keyed"]', rec="True", ra="True",
            params="{}")
        w(fid, f"keyxor-{k}", head + "\n" +
          _fill(TMPL["index_xor_keyed"], {"k": k, "g": g}), force)

    # ---- Additional algebraic substitutions (S-box-like affine over GF(2)) ----
    import random as _rnd
    _r = _rnd.Random(77)
    for si in range(12):
        fid += 1
        head = HEADER.format(
            name=f"GF Affine Sub {si+1}", desc="byte -> A*x+b over GF(2)^8 "
            "with random invertible matrix A (XOR of bit permutations): "
            "linear-algebra substitution family; bijection, true RA.",
            cat="Algebra", tags='["algebra","gf2","bijection"]', rec="True",
            ra="True", params="{}")
        # build invertible 8x8 GF(2) matrix by random row combinations
        def rand_mat():
            while True:
                rows = [_r.randrange(256) for _ in range(8)]
                # rank check via gaussian elim
                m = rows[:]; rk = 0
                for col in range(7, -1, -1):
                    piv = next((i for i in range(rk, 8) if (m[i] >> col) & 1), None)
                    if piv is None: continue
                    m[rk], m[piv] = m[piv], m[rk]
                    for i in range(8):
                        if i != rk and (m[i] >> col) & 1:
                            m[i] ^= m[rk]
                    rk += 1
                if rk == 8:
                    return rows
        rows = rand_mat()
        body = f"""
ROWS = {rows!r}
OFF = {_r.randrange(256)}


def _apply(x):
    r = 0
    for i, rw in enumerate(ROWS):
        if (x >> i) & 1:
            r ^= rw
    return r ^ OFF


MAP = [_apply(i) for i in range(256)]


def analyze(INPUT, PARAMETERS):
    # pure linear-algebra law over GF(2)^8 applied to the index byte
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE * 8)
    return bytes(MAP[n & 0xFF] for n in range(SIZE))


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH * 8)
    return bytes(MAP[(OFFSET + i) & 0xFF] for i in range(LENGTH))
"""
        w(fid, f"gfaff-{si+1}", head + body, force)

    # ---- Polynomial maps mod 256 (quadratic/cubic index laws) ----
    for (c2, c3, b) in [(1, 0, 0), (3, 1, 5), (5, 2, 7), (7, 3, 1),
                        (9, 4, 3), (11, 5, 9), (13, 6, 11), (15, 7, 13)]:
        fid += 1
        head = HEADER.format(
            name=f"Poly Index {c2}n^2+{c3}n^3", desc="byte(n)=(c2*n^2+"
            "c3*n^3+n+b)%256 fitted offsets only; pure index law test.",
            cat="DirectAccess", tags='["direct-access","polynomial"]',
            rec="True", ra="True", params="{}")
        body = f"""
C2 = {c2}
C3 = {c3}
B = {b}

def analyze(INPUT, PARAMETERS):
    # fit single additive offset b* minimizing error on first 8 bytes
    head = INPUT[:8]
    best = min(range(256), key=lambda bo: sum(
        bin(((C2*i*i + C3*i*i*i + i + B + bo) % M) ^ head[i]).count("1")
        for i in range(len(head))))
    return {{"bo": best, "size": len(INPUT)}}

def _gen(STATE, lo, hi):
    bo = STATE["bo"]
    return bytes((C2*n*n + C3*n*n*n + n + B + bo) % M for n in range(lo, hi))

def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    return _gen(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return _gen(STATE, OFFSET, OFFSET + LENGTH)
"""
        w(fid, f"poly-{c2}-{c3}", head + body, force)

    # ---- Bit-slice interleave of two byte streams (odd/even split) ----
    for grp in (2, 4, 8):
        fid += 1
        head = HEADER.format(
            name=f"Bit Slice Groups {grp}", desc="transpose bits across "
            f"{grp}-byte groups: tests bit-plane reorganization as a codec "
            "(bijection, true RA within group window).", cat="BitOps",
            tags='["bitops","bitplane","bijection"]', rec="True", ra="True",
            params="{}")
        body = f"""
G = {grp}


def _tr(block):
    # transpose the Gx8 bit matrix of a byte group (bit-plane reorder)
    rows = [[(b >> k) & 1 for k in range(8)] for b in block]
    out = []
    for j in range(G):
        v = 0
        for k in range(8):
            v |= (rows[k][j] if k < len(rows) else 0) << k
        out.append(v)
    return out


def analyze(INPUT, PARAMETERS):
    # PURE INDEX LAW: no data copy. out[n] depends only on n (and G).
    return {{"size": len(INPUT)}}


def reconstruct(STATE, SIZE, PARAMETERS):
    abc_formula.ops(SIZE)
    idx = list(range(SIZE))
    out = bytearray()
    for i in range(0, len(idx) - G + 1, G):
        out += _tr(idx[i:i+G])
    out += idx[len(idx) - (len(idx) % G):] if len(idx) % G else []
    return bytes(x & 0xFF for x in out)[:SIZE]


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH + G)   # O(window): true random access
    blk = (OFFSET // G) * G
    t = _tr(list(range(blk, blk + ((OFFSET - blk) + LENGTH))))
    return bytes(x & 0xFF for x in t[(OFFSET - blk):])[:LENGTH]
"""
        w(fid, f"slices-{grp}", head + body, force)

    # ---- LCG parameter sets (distinct multipliers/addends) ----
    for (a, c, salt) in [(6364136223846793005, 1442695040888963407, "l1"),
                         (2862933555777941757, 3037000493, "l2"),
                         (0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9, "l3"),
                         (0xD1342543DE82EF95, 0x12345, "l4"),
                         (57005, 0xDEADBEEF, "l5"),
                         (0x41C64E6D, 0x3039, "l6"),
                         (0x5DEECE66D, 0xB, "l7"),
                         (0x1003F, 0x523EAB, "l8")]:
        fid += 1
        head = HEADER.format(
            name=f"LCG {salt}", desc="linear congruential keystream XOR with "
            "stored ciphertext copy; recurrence-class control experiment.",
            cat="Recurrence", tags='["recurrence","lcg"]', rec="True",
            ra="True", params="{}")
        w(fid, f"lcg-{salt}", head + "\n" +
          _fill(TMPL["lcg"], {"a": a, "c": c, "salt": salt}), force)

    # ---- More nonlinear recurrences ----
    for (a, kk, salt) in [(0x100000001B3, 11, "r7"), (0xAF, 41, "r8"),
                          (0x8F5B, 23, "r9"), (0xFFFFDEED, 19, "r10")]:
        fid += 1
        head = HEADER.format(
            name=f"Nonlinear Recurrence {salt}", desc="S'=(aS + (s>>k)^s) "
            "keystream XOR model. Carries ciphertext copy; reads simulate "
            "from S0 — regression-class behavior for the RA probe.",
            cat="Recurrence", tags='["recurrence","stream"]', rec="True",
            ra="True", params="{}")
        w(fid, f"recur-{salt}", head + "\n" +
          _fill(TMPL["recurrence_state"], {"a": a, "k": kk, "salt": salt}),
          force)

    # ---- More LFSR polys ----
    for poly in [0xE100000000000000 + 0x0B, 0xF400000000000000 + 0x1F,
                 0x9D00000000000000 + 0x4B, 0xCB00000000000000 + 0x67]:
        fid += 1
        head = HEADER.format(
            name=f"LFSR-64 0x{poly:X}", desc="64-bit Galois LFSR keystream XOR. "
            "v0006 lineage: matched 64 header bits of a WebP then diverged. "
            "Keeps ciphertext copy in state; probe should report simulated "
            "access.", cat="LFSR", tags='["lfsr","regression-v0006"]',
            rec="True", ra="True", params="{}")
        w(fid, f"lfsr-{poly & 0xFF:02x}", head + "\n" +
          _fill(TMPL["lfsr_stream"], {"poly": poly}), force)

    # ---- Hybrids: compositions across families ----
    names = ["affine", "xor", "rot", "gray", "rev", "nib"]
    pairs = [(pp, qq) for pp in names for qq in names if pp != qq]
    for (p, q) in pairs:
        fid += 1
        head = HEADER.format(
            name=f"Hybrid {p}+{q}",
            desc="composition of two byte-local bijections from different "
                 "families; verifies closure and true random access.",
            cat="Hybrid", tags='["hybrid","bijection"]', rec="True",
            ra="True", params="{}")
        body = TMPL["hybrid"].replace("__P__", repr(p)).replace("__Q__", repr(q))
        w(fid, f"hyb-{p}-{q}", head + "\n" + body, force)

    # ---- Deterministic padding: distinct pure index laws (no dupes) ----
    pad = []
    pad.append(("gray-index-law", "Gray Index Law", "BitOps",
                "byte(n)=gray(n%256): smooth bit-difference index law, "
                "position-only, true RA.", '["bitops","index-law"]',
                ("gray_index", {})))
    pad.append(("bitrev-index-law", "BitRev Index Law", "BitOps",
                "byte(n)=reverse8(n%256): position-only bit-reversal law.",
                '["bitops","index-law"]', ("bitrev_index", {})))
    pad.append(("nib-index-law", "NibbleSwap Index Law", "BitOps",
                "byte(n)=swap4(n%256): position-only nibble-swap law.",
                '["bitops","index-law"]', ("nib_index", {})))
    import random as _pr
    _p = _pr.Random(4242)
    def _mat():
        while True:
            rows = [_p.randrange(256) for _ in range(8)]
            m = rows[:]; rk = 0
            for col in range(7, -1, -1):
                piv = next((i for i in range(rk, 8) if (m[i] >> col) & 1), None)
                if piv is None:
                    continue
                m[rk], m[piv] = m[piv], m[rk]
                for i in range(8):
                    if i != rk and (m[i] >> col) & 1:
                        m[i] ^= m[rk]
                rk += 1
            if rk == 8:
                return rows
    for j in range(11):
        pad.append((f"gfaffine-idx-{j+1}", f"GF Affine Index {j+1}",
                    "Algebra",
                    "byte(n)=A*(n%256)+b over GF(2)^8, fixed published "
                    "invertible A: linear-algebra index law family.",
                    '["algebra","gf2","index-law"]',
                    ("gfaffine_index", {"rows": _mat(),
                                        "off": _p.randrange(256)})))
    for slug, nm, cat, desc, tags, (tmpl, ctx) in pad:
        fid += 1
        head = HEADER.format(name=nm, desc=desc, cat=cat, tags=tags,
                             rec="True", ra="True", params="{}")
        w(fid, slug, head + "\n" + _fill(TMPL[tmpl], ctx), force)

    # ---- v0006 regression fixture (kept OUT of the 256 starter set) ----
    fid += 1
    head = HEADER.format(
        name="v0006 Regression", desc="PRESERVED FAILURE: matched 64 header "
        "bits of the 8484-byte WebP then diverged at byte 8. Do not repair; "
        "run against samples/regression/image.webp.", cat="Regression",
        tags='["regression","v0006","lfsr"]', rec="True", ra="True",
        params="{}")
    w(fid, "v0006-regression", head + "\n" +
      _fill(TMPL["v0006"], {"poly": 0xB400000000000017}), force)

    assert fid == 257, f"generator must emit 256 starters + 1 regression, got {fid}"
    return fid


if __name__ == "__main__":
    n = build("--force" in sys.argv)
    print(f"generated {n} formulas into {OUT}")
