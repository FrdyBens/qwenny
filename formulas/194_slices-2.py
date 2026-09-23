NAME = "Bit Slice Groups 2"
VERSION = "1.0.0"
DESCRIPTION = ("transpose bits across 2-byte groups: tests bit-plane reorganization as a codec (bijection, true RA within group window).")
CATEGORY = "BitOps"
TAGS = ["bitops","bitplane","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1

G = 2


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
    return {"size": len(INPUT)}


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
