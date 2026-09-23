NAME = "Direct Index P=3"
VERSION = "1.0.0"
DESCRIPTION = ("bit(n)=F(params,n): hash-chain of 3 fitted params drives each bit. Tiny state => expect ~50% BER on random data; any lower BER on structured data is the signal worth studying.")
CATEGORY = "DirectAccess"
TAGS = ["direct-access","index-law"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1


# Direct-index family: bit(n) = F(params, n) with params FITTED to input.
# Family question: how many parameters does F need to fit real data?
# We fit NOTHING here beyond a small header; output is a deterministic
# function of index only, so mismatch is expected and informative.
P = 3      # parameter count
MODE = 12

def _bit(n, ps):
    h = n
    for j in range(len(ps)):
        h = (h * 0x100000001B3) ^ ps[j]
        h &= MASK
    return (h >> (11)) & 1

def analyze(INPUT, PARAMETERS):
    import hashlib
    # Parameters are DERIVED FROM INPUT during analysis (legitimate fitting);
    # they are tiny, which means prediction quality on arbitrary data should
    # be ~coin-flip. BER tells us exactly that.
    d = hashlib.sha256(INPUT).digest()
    ps = [int.from_bytes(d[i*8:(i+1)*8], "big") for i in range(P)]
    return {"ps": ps, "size": len(INPUT), "mode": MODE}

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
