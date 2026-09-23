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


# Direct-index law bit(n)=F(key,n), key fitted from input digest during
# analysis. Key size counted honestly: with K<<N words it cannot carry N
# bytes of entropy; BER near 0.5 on random data proves the limit.
K = 32          # key words
G = 7809847782465536322          # mixing constant


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
    seed = int.from_bytes(hashlib.sha256(b"abc-keyxor-32").digest()[:8], "big")
    return {"seed": seed, "size": len(INPUT)}


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
