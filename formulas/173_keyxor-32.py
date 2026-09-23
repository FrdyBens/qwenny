NAME = "Keyed XOR Words 32"
VERSION = "1.0.0"
DESCRIPTION = ("32-word PRNG key XOR; tests whether keying by content digest ever shrinks state (it cannot — measure the illusion).")
CATEGORY = "Experimental"
TAGS = ["experimental","keyed"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# byte(n) = data-free keyed map over index only? No — analysis extracts a
# per-position residual vs the model; tests how well F(params,n) predicts
# arbitrary bytes. KEY derived from input digest is NOT reconstruction info
# beyond the stored key itself (key size counted honestly in state).
K = 32          # key words
G = 7809847782465536322          # mixing constant

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
    return {"seed": seed, "size": L,
            "enc_b64": __import__("base64").b64encode(bytes(enc)).decode()}

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
