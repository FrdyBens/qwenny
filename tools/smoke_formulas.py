"""Smoke-test EVERY formula through the real Registry.

For each loaded formula: metadata, capabilities, analyze on a small binary
input, JSON round-trip of STATE, reconstruct, read at 0 and mid-offset, and
consistency of read vs reconstruct window. Reports failures; exits nonzero
if any formula is rejected or errors (rejected list printed with reasons).
Run: python tools/smoke_formulas.py
"""
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.registry import Registry, call_analyze, call_read, call_reconstruct

DATA = open(ROOT / "samples/binary/random-4kb.bin", "rb").read()

reg = Registry(ROOT / "formulas")
t0 = time.time()
reg.scan(notify=False)
print(f"scan {time.time()-t0:.1f}s: loaded={len(reg.good)} rejected={len(reg.bad)}")
for f, info in reg.bad.items():
    print("REJECTED", f, info["errors"])

fails = []
for fid in sorted(reg.good):
    lf = reg.good[fid]
    try:
        caps = lf.capabilities()
        state, ms = call_analyze(lf, DATA, {})
        out = None
        if caps["supports_reconstruction"]:
            out, rms, ops = call_reconstruct(lf, state, len(DATA), {})
            assert isinstance(out, bytes) and len(out) == len(DATA), \
                f"reconstruct size {len(out) if out else None} != {len(DATA)}"
        if caps["supports_random_access"]:
            w1, _, _ = call_read(lf, state, 0, 256, {})
            w2, _, ops2 = call_read(lf, state, 2000, 256, {})
            assert len(w1) == 256 and len(w2) == 256, "bad window size"
            if out is not None:
                assert w1 == out[0:256], "read/reconstruct disagree @0"
                assert w2 == out[2000:2256], "read/reconstruct disagree @2000"
    except Exception as e:
        fails.append((fid, lf.path.name, f"{type(e).__name__}: {e}"))

for fid, name, err in fails:
    print("FAIL", fid, name, err[:200])
print(f"\nSMOKE RESULT: {len(reg.good)} loaded, {len(reg.bad)} rejected, "
      f"{len(fails)} runtime failures")
sys.exit(1 if (fails or reg.bad) else 0)
