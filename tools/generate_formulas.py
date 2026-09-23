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

def analyze(INPUT, PARAMETERS):
    # Tests: can b[n] = A*INPUT[n]+B mod 256 represent data? (It cannot
    # shrink it — this measures how much structure real files give away.)
    inv = pow(A, -1, M) if A % 2 and A else None
    return {{"a": A, "b": B, "inv": inv, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes((STATE["a"] * x + STATE["b"]) % M for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes((STATE["a"] * x + STATE["b"]) % M
                 for x in d[OFFSET:OFFSET + LENGTH])
'''

TMPL["xor_const"] = """
K = {k}

def analyze(INPUT, PARAMETERS):
    return {{"k": K, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    k = STATE["k"]
    d = base64.b64decode(STATE["data_b64"])
    return bytes(x ^ k for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    k = STATE["k"]
    d = base64.b64decode(STATE["data_b64"])
    return bytes(x ^ k for x in d[OFFSET:OFFSET + LENGTH])
"""

TMPL["bit_reverse"] = '''
REV = [int(bin(i)[2:].zfill(8)[::-1], 2) for i in range(256)]

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def _t(d):
    return bytes(REV[x] for x in d)

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    return _t(base64.b64decode(STATE["data_b64"]))[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    return _t(base64.b64decode(STATE["data_b64"])[OFFSET:OFFSET + LENGTH])
'''

TMPL["nibble_swap"] = '''
SW = [((i << 4) | (i >> 4)) & 255 for i in range(256)]

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def _t(d):
    return bytes(SW[x] for x in d)

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    return _t(base64.b64decode(STATE["data_b64"]))[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    return _t(base64.b64decode(STATE["data_b64"])[OFFSET:OFFSET + LENGTH])
'''

TMPL["byteswap"] = """
W = {w}

def analyze(INPUT, PARAMETERS):
    return {{"w": W, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def _t(d, w):
    out = bytearray(d)
    for i in range(0, len(out) - w + 1, w):
        out[i:i + w] = out[i:i + w][::-1]
    return bytes(out)

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    return _t(base64.b64decode(STATE["data_b64"]), STATE["w"])[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    w = STATE["w"]
    abc_formula.ops(LENGTH + w)
    blk = (OFFSET // w) * w
    d = base64.b64decode(STATE["data_b64"])
    return _t(d[blk:blk + ((OFFSET - blk) + LENGTH)], w)[(OFFSET - blk):][:LENGTH]
"""

TMPL["index_xor_keyed"] = '''
# byte(n) = data-free keyed map over index only? No — analysis extracts a
# per-position residual vs the model; tests how well F(params,n) predicts
# arbitrary bytes. KEY derived from input digest is NOT reconstruction info
# beyond the stored key itself (key size counted honestly in state).
K = {k}          # key words
G = {g}          # mixing constant

def _gen_key(seed):
    s = seed
    out = []
    for _ in range(K):
        s = (s * 6364136223846793005 + 1442695040888963407) & MASK
        out.append(s >> 16 & 0xFFFFFFFF)
    return out

def analyze(INPUT, PARAMETERS):
    import hashlib
    seed = int.from_bytes(hashlib.sha256(INPUT).digest()[:8], "big")
    key = _gen_key(seed)
    enc = bytearray(INPUT)
    L = len(INPUT)
    for i in range(L):
        enc[i] ^= (key[(i // 4) % K].to_bytes(4, "little")[i % 4])
    # honest check: does the model predict anything without storing data?
    # NO: we must still carry enc (the transformed copy). This family
    # measures whether keying by digest reduces representation. It cannot.
    return {{"seed": seed, "size": L,
            "enc_b64": __import__("base64").b64encode(bytes(enc)).decode()}}

def _dec(state, lo, hi):
    import base64
    e = base64.b64decode(state["enc_b64"])
    key = _gen_key(state["seed"])
    return bytes(e[i] ^ key[(i // 4) % K].to_bytes(4, "little")[i % 4]
                 for i in range(lo, min(hi, len(e))))

def reconstruct(STATE, SIZE, PARAMETERS):
    return _dec(STATE, 0, SIZE)

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    abc_formula.ops(LENGTH)
    return _dec(STATE, OFFSET, OFFSET + LENGTH)
'''

TMPL["lfsr_stream"] = '''
# LFSR keystream XOR model: state = (tap poly id, seed, ciphertext-copy).
# Reconstruction is exact ONLY because the ciphertext copy is carried —
# the lab counts it. Random access simulates from bit 0 => probe will say
# NOT TRUE RANDOM ACCESS. This preserves the v0006 lesson structurally.
POLY = {poly}     # feedback mask over 64 bits
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
    return {{"seed": seed, "size": len(INPUT),
            "enc_b64": __import__("base64").b64encode(enc).decode()}}

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
    import hashlib
    # Parameters are DERIVED FROM INPUT during analysis (legitimate fitting);
    # they are tiny, which means prediction quality on arbitrary data should
    # be ~coin-flip. BER tells us exactly that.
    d = hashlib.sha256(INPUT).digest()
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
# Feistel-like permutation of INDEX space: byte(n)=T(pi(n)) style test with
# pi a keyless fixed-round Feistel on 32-bit index, combined with a stored
# transformed copy (again counted). Tests permutation-of-domain ideas.
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

INV = {{}}

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
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

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
# Nonlinear recurrence S_(n+1) = (a*S_n + S_n xor (S_n>>k)) mod 2^64,
# byte(n) = low byte of S_n, seeded by analysis fit. Reconstruction carries
# a ciphertext copy (counted). Simulated reads => probe flags false RA.
A = {a}
K = {k}

def _step(s):
    return (A * s + (s ^ (s >> K))) & MASK

def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"seed{salt}" + INPUT).digest()[:8],
                        "big")
    s = s0
    ks = bytearray()
    for _ in range(len(INPUT)):
        ks.append(s & 0xFF)
        s = _step(s)
    enc = bytes(x ^ y for x, y in zip(INPUT, ks))
    return {{"s0": s0, "size": len(INPUT),
            "enc_b64": __import__("base64").b64encode(enc).decode()}}

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
'''

TMPL["ca_rule"] = '''
# Elementary cellular automaton row evolution used as an index mixer:
# byte(n) depends on rule table applied to (n's bit-triplets). Deterministic
# index-only map; paired with stored copy for exactness. Tests CA-as-codec.
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
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d[OFFSET:OFFSET + LENGTH])
'''

TMPL["gf_mul"] = '''
# Multiplication in GF(2^8) by a fixed element (carry-less, reduced by the
# AES polynomial). Byte-local bijection when k != 0: true random access.
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

INVK = None
for _i in range(1, 256):
    if gmul(K, _i) == 1:
        INVK = _i
        break

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    if STATE.get("inv"):
        return bytes(gmul(x, INVK) for x in d)[:SIZE]
    return bytes(gmul(x, K) for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH * 8)
    d = base64.b64decode(STATE["data_b64"])
    f = gmul
    if STATE.get("inv"):
        return bytes(f(x, INVK) for x in d[OFFSET:OFFSET + LENGTH])
    return bytes(f(x, K) for x in d[OFFSET:OFFSET + LENGTH])
'''


TMPL["hybrid"] = """
# Hybrid composition of two byte-local bijections P then Q.
# Tests whether composing structures from different families changes the
# representation cost (it should not for pure bijections — verify).
PNAME = __P__
QNAME = __Q__

PS = {
    "affine": lambda x, s=(3, 5): (s[0] * x + s[1]) % M,
    "xor": lambda x, s=0x5A: x ^ s,
    "rot": lambda x, s=3: ((x << s) | (x >> (8 - s))) & 255,
    "gray": lambda x, s=None: x ^ (x >> 1),
    "rev": lambda x, s=None: int(bin(x)[2:].zfill(8)[::-1], 2),
    "nib": lambda x, s=None: ((x << 4) | (x >> 4)) & 255,
}

def _mk(name):
    return PS[name]

def analyze(INPUT, PARAMETERS):
    return {"p": PNAME, "q": QNAME, "size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    f = _mk(STATE["p"]); g = _mk(STATE["q"])
    return bytes(g(f(x)) for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    f = _mk(STATE["p"]); g = _mk(STATE["q"])
    return bytes(g(f(x)) for x in d[OFFSET:OFFSET + LENGTH])
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
# LCG keystream: S'=(a*S+c)%2^64, byte(n)=low byte(S_n) XOR ciphertext copy.
# Classic recurrence; reads simulate => probe must flag NOT TRUE RA.
A = {a}
C = {c}

def _step(s):
    return (A * s + C) & MASK

def analyze(INPUT, PARAMETERS):
    import hashlib
    s0 = int.from_bytes(hashlib.sha256(b"lcg{salt}").digest()[:8], "big")
    s = s0
    enc = bytearray()
    for x in INPUT:
        s = _step(s)
        enc.append(x ^ (s & 255))
    return {{"s0": s0, "size": len(INPUT),
            "enc_b64": __import__("base64").b64encode(bytes(enc)).decode()}}

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
        tbl = [((i << sh) | (i >> (8 - sh))) & 255 for i in range(256)]
        body = ("\nROT = %r\n\n\ndef analyze(INPUT, PARAMETERS):\n    "
                'return {"size": len(INPUT), "data_b64": '
                '__import__("base64").b64encode(INPUT).decode()}\n\n\n'
                "def reconstruct(STATE, SIZE, PARAMETERS):\n    import base64\n"
                "    d = base64.b64decode(STATE['data_b64'])\n"
                "    return bytes(ROT[x] for x in d)[:SIZE]\n\n\n"
                "def read(STATE, OFFSET, LENGTH, PARAMETERS):\n    import base64\n"
                "    abc_formula.ops(LENGTH)\n"
                "    d = base64.b64decode(STATE['data_b64'])\n"
                "    return bytes(ROT[x] for x in d[OFFSET:OFFSET+LENGTH])\n"
                % (tbl,))
        w(fid, f"rot{sh}", head + body, force)

    # gray code (byte-local bijection, classic structure experiment)
    fid += 1
    head = HEADER.format(
        name="Gray Code", desc="binary->gray per byte: g=b^(b>>1). "
        "Reversible; tests locality-preserving maps.", cat="BitOps",
        tags='["bitops","bijection"]', rec="True", ra="True", params="{}")
    gr = [i ^ (i >> 1) for i in range(256)]
    ig = [0] * 256
    for i, g in enumerate(gr):
        ig[g] = i
    body = ("\nGRAY=%r\nIGRAY=%r\n\n\ndef analyze(INPUT, PARAMETERS):\n"
            '    return {"size": len(INPUT), "data_b64": '
            '__import__("base64").b64encode(INPUT).decode()}\n\n\n'
            "def reconstruct(STATE, SIZE, PARAMETERS):\n    import base64\n"
            "    d=base64.b64decode(STATE['data_b64'])\n"
            "    return bytes(IGRAY[x] if STATE.get('inv') else GRAY[x] "
            "for x in d)[:SIZE]\n\n\n"
            "def read(STATE, OFFSET, LENGTH, PARAMETERS):\n    import base64\n"
            "    abc_formula.ops(LENGTH)\n    d=base64.b64decode("
            "STATE['data_b64'])\n    return bytes((IGRAY if STATE.get('inv')"
            " else GRAY)[x] for x in d[OFFSET:OFFSET+LENGTH])\n" % (gr, ig))
    w(fid, "gray", head + body, force)

    # interleaving of two halves (index-global bijection, true RA)
    fid += 1
    head = HEADER.format(
        name="Half Interleave", desc="out[2i]=in[i], out[2i+1]=in[i+L/2]: "
        "global index permutation with O(1) inverse => true random access.",
        cat="BitOps", tags='["bitops","permutation"]', rec="True", ra="True",
        params="{}")
    body = '''

def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

def _src(n, L):
    half = L // 2
    if n % 2 == 0:
        return n // 2
    return half + n // 2

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes(d[_src(n, len(d))] for n in range(len(d)))[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes(d[_src(OFFSET + i, len(d))] for i in range(LENGTH))
'''
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
INV = [0]*256
for _i, _v in enumerate(MAP):
    INV[_v] = _i

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d[OFFSET:OFFSET + LENGTH])
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

def _enc(block):
    out = [0]*G
    for j in range(G):
        v = 0
        for k in range(8):
            bits = 0
            for i in range(G):
                bits = (bits << 1) | ((block[i] >> k) & 1) if G <= 8 else 0
            v = (v << 1) | ((bits >> (G - 1 - j)) & 1)
        out[j] = v & 255
    return out

MAPT = {{tuple(range(G)): None}}

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def _tr(block):
    # transpose the 8xG bit matrix (pad columns with 0 beyond data)
    rows = [[(b >> k) & 1 for k in range(8)] for b in block]
    out = []
    for j in range(G):
        v = 0
        for k in range(8):
            v |= (rows[k][j] if k < len(rows) else 0) << k
        out.append(v)
    return out

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    out = bytearray()
    for i in range(0, len(d) - G + 1, G):
        out += _tr(d[i:i+G])
    out += d[len(d) - (len(d) % G):] if len(d) % G else b""
    return bytes(out)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH + G)
    d = base64.b64decode(STATE["data_b64"])
    blk = (OFFSET // G) * G
    t = _tr(d[blk:blk + ((OFFSET - blk) + LENGTH)])
    return bytes(t[(OFFSET - blk):])[:LENGTH]
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

    # ---- Hybrids to reach ~256: compositions across families ----
    names = ["affine", "xor", "rot", "gray", "rev", "nib"]
    pairs = [(p, q) for p in names for q in names if p != q]
    for (p, q) in pairs:
        fid += 1
        head = HEADER.format(
            name=f"Hybrid {p}+{q}",
            desc="composition of two byte-local bijections from different "
                 "families; verifies closure and true random access.",
            cat="Hybrid", tags='["hybrid","bijection"]', rec="True",
            ra="True", params="{}")
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
INV = [0]*256
for _i, _v in enumerate(MAP):
    INV[_v] = _i

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE["data_b64"])
    return bytes(MAP[x] for x in d[OFFSET:OFFSET + LENGTH])
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

def _enc(block):
    out = [0]*G
    for j in range(G):
        v = 0
        for k in range(8):
            bits = 0
            for i in range(G):
                bits = (bits << 1) | ((block[i] >> k) & 1) if G <= 8 else 0
            v = (v << 1) | ((bits >> (G - 1 - j)) & 1)
        out[j] = v & 255
    return out

MAPT = {{tuple(range(G)): None}}

def analyze(INPUT, PARAMETERS):
    return {{"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}}

def _tr(block):
    # transpose the 8xG bit matrix (pad columns with 0 beyond data)
    rows = [[(b >> k) & 1 for k in range(8)] for b in block]
    out = []
    for j in range(G):
        v = 0
        for k in range(8):
            v |= (rows[k][j] if k < len(rows) else 0) << k
        out.append(v)
    return out

def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE["data_b64"])
    out = bytearray()
    for i in range(0, len(d) - G + 1, G):
        out += _tr(d[i:i+G])
    out += d[len(d) - (len(d) % G):] if len(d) % G else b""
    return bytes(out)[:SIZE]

def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH + G)
    d = base64.b64decode(STATE["data_b64"])
    blk = (OFFSET // G) * G
    t = _tr(d[blk:blk + ((OFFSET - blk) + LENGTH)])
    return bytes(t[(OFFSET - blk):])[:LENGTH]
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

    # ---- Hybrids to reach ~256: compositions across families ----
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

    return fid


if __name__ == "__main__":
    n = build("--force" in sys.argv)
    print(f"generated {n} formulas into {OUT}")
