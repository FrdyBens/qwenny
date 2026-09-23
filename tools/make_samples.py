"""Deterministic sample generator (fixed seeds -> reproducible experiments).

Creates:
  samples/text/hello.txt
  samples/binary/random-{1,4,16,64}kb.bin   deterministic PRNG bytes
  samples/binary/zeros-1kb.bin              degenerate low-entropy control
  samples/binary/gradient-4kb.bin           smooth byte ramp (structured)
  samples/binary/image.webp                 8484-byte RIFF/WEBP container
       — reproduces the v0006 regression conditions exactly: 8-byte header
         any byte-affine model can match, entropy body diverging at byte 8.
Run:  python tools/make_samples.py   (idempotent)

Random data is the honest adversary of weak formulas — structured files can
make trivial math look successful. Keep these seeds fixed.
"""
from __future__ import annotations

import hashlib
import random
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def struct_le32(n: int) -> bytes:
    return bytes([n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >> 24) & 255])


def chunk(tag: bytes, payload: bytes) -> bytes:
    return struct_le32(len(payload)) + tag + payload + \
        struct_le32(zlib.crc32(tag + payload) & 0xFFFFFFFF)


def make_webp(width: int, height: int) -> bytes:
    """Structurally real WebP framing (RIFF....WEBP + VP8L chunk). The image
    does not need to be decodable by viewers; what matters for the lab is the
    byte pattern: a low-entropy 8-byte-aligned header followed by a
    high-entropy body — precisely where v0006 matched 64 bits then diverged."""
    body = bytearray()
    rng = random.Random(0xC0FFEE)
    body += b"\x2f" + struct_le32(((width - 1) & 0x3FFF) |
                                  ((height - 1) << 14))[:3] + b"\x00"
    while len(body) < 8460:
        body.append(rng.randrange(256))
    vp8l = chunk(b"VP8L", bytes(body))
    riff = b"RIFF" + struct_le32(4 + len(vp8l)) + b"WEBP" + vp8l
    assert len(riff) == 8484, len(riff)
    return bytes(riff)


def main() -> None:
    for d in ("text", "images", "video", "binary", "custom"):
        (ROOT / "samples" / d).mkdir(parents=True, exist_ok=True)

    def write(rel: str, data: bytes) -> None:
        p = ROOT / "samples" / rel
        if p.exists() and p.read_bytes() == data:
            print(f"unchanged {rel}")
            return
        p.write_bytes(data)
        print(f"wrote {rel} ({len(data)} B)")

    write("text/hello.txt",
          ("Hello ABC-INFINITY\n"
           "The quick brown fox jumps over the lazy dog.\n" * 4).encode())
    for kb in (1, 4, 16, 64):
        rng = random.Random(1234 + kb)          # FIXED seed
        write(f"binary/random-{kb}kb.bin",
              bytes(rng.randrange(256) for _ in range(kb * 1024)))
    write("binary/zeros-1kb.bin", bytes(1024))
    write("binary/gradient-4kb.bin", bytes(i % 256 for i in range(4096)))
    write("binary/image.webp", make_webp(128, 100))
    # sanity: first 8 bytes are the classic RIFF prefix users expect to see
    w = (ROOT / "samples" / "binary" / "image.webp").read_bytes()
    print("webp head:", w[:12].hex(" "), "size", len(w))
    assert w[:4] == b"RIFF" and w[8:12] == b"WEBP"


if __name__ == "__main__":
    main()
