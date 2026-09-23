NAME = "Rotate 5"
VERSION = "1.0.0"
DESCRIPTION = ("circular rotate left by 5 bits.")
CATEGORY = "BitOps"
TAGS = ["bitops","bijection"]
SUPPORTS_ANALYSIS = True
SUPPORTS_RECONSTRUCTION = True
SUPPORTS_RANDOM_ACCESS = True
SUPPORTS_STREAMING = False
PARAMETERS = {}

from contract import FormulaError  # noqa: E402
import abc_formula                 # noqa: E710,E402

M = 256
MASK = (1 << 64) - 1

ROT = [0, 32, 64, 96, 128, 160, 192, 224, 1, 33, 65, 97, 129, 161, 193, 225, 2, 34, 66, 98, 130, 162, 194, 226, 3, 35, 67, 99, 131, 163, 195, 227, 4, 36, 68, 100, 132, 164, 196, 228, 5, 37, 69, 101, 133, 165, 197, 229, 6, 38, 70, 102, 134, 166, 198, 230, 7, 39, 71, 103, 135, 167, 199, 231, 8, 40, 72, 104, 136, 168, 200, 232, 9, 41, 73, 105, 137, 169, 201, 233, 10, 42, 74, 106, 138, 170, 202, 234, 11, 43, 75, 107, 139, 171, 203, 235, 12, 44, 76, 108, 140, 172, 204, 236, 13, 45, 77, 109, 141, 173, 205, 237, 14, 46, 78, 110, 142, 174, 206, 238, 15, 47, 79, 111, 143, 175, 207, 239, 16, 48, 80, 112, 144, 176, 208, 240, 17, 49, 81, 113, 145, 177, 209, 241, 18, 50, 82, 114, 146, 178, 210, 242, 19, 51, 83, 115, 147, 179, 211, 243, 20, 52, 84, 116, 148, 180, 212, 244, 21, 53, 85, 117, 149, 181, 213, 245, 22, 54, 86, 118, 150, 182, 214, 246, 23, 55, 87, 119, 151, 183, 215, 247, 24, 56, 88, 120, 152, 184, 216, 248, 25, 57, 89, 121, 153, 185, 217, 249, 26, 58, 90, 122, 154, 186, 218, 250, 27, 59, 91, 123, 155, 187, 219, 251, 28, 60, 92, 124, 156, 188, 220, 252, 29, 61, 93, 125, 157, 189, 221, 253, 30, 62, 94, 126, 158, 190, 222, 254, 31, 63, 95, 127, 159, 191, 223, 255]


def analyze(INPUT, PARAMETERS):
    return {"size": len(INPUT), "data_b64": __import__("base64").b64encode(INPUT).decode()}


def reconstruct(STATE, SIZE, PARAMETERS):
    import base64
    d = base64.b64decode(STATE['data_b64'])
    return bytes(ROT[x] for x in d)[:SIZE]


def read(STATE, OFFSET, LENGTH, PARAMETERS):
    import base64
    abc_formula.ops(LENGTH)
    d = base64.b64decode(STATE['data_b64'])
    return bytes(ROT[x] for x in d[OFFSET:OFFSET+LENGTH])
