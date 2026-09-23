NAME = "Bit Slice Groups 4"
VERSION = "1.0.0"
DESCRIPTION = ("transpose bits across 4-byte groups: tests bit-plane reorganization as a codec (bijection, true RA within group window).")
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

G = 4

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

MAPT = {tuple(range(G)): None}

def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT),
            "data_b64": __import__("base64").b64encode(INPUT).decode()}

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
