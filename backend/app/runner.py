"""Experiment runner: analyze -> reconstruct -> seek-reads, with honest
verification and true-random-access instrumentation.

Key guarantees:
- INPUT bytes are passed ONLY to analyze(). reconstruct()/read() receive a
  JSON round-tripped copy of STATE (see registry.call_*).
- Invalid seeks (offset+length beyond input size) return INVALID_SEEK and can
  never degrade into an empty-vs-empty "match".
- Random access is classified from measured ops-per-read at multiple offsets:
  O(1)-ish => TRUE RANDOM ACCESS; cost growing with offset => slicing /
  sequential simulation ("NOT TRUE RANDOM ACCESS").
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from . import metrics
from .contract import FormulaError
from .registry import Registry, call_analyze, call_read, call_reconstruct

MAX_PREVIEW = 4096          # bytes of hex preview returned per side
SEEK_PROBE_LENGTH = 256     # window used for random-access probes


class SeekError(Exception):
    pass


def validate_seek(size: int, offset: int, length: int) -> None:
    if not isinstance(offset, int) or not isinstance(length, int):
        raise SeekError("OFFSET and LENGTH must be integers")
    if length <= 0:
        raise SeekError(f"LENGTH must be > 0 (got {length})")
    if offset < 0:
        raise SeekError(f"OFFSET must be >= 0 (got {offset})")
    if offset >= size:
        raise SeekError(
            f"Offset {offset} is outside file size {size}.")
    if offset + length > size:
        raise SeekError(
            f"Offset {offset} + Length {length} exceeds file size {size} "
            f"(only {size - offset} bytes available).")


def _preview(data: bytes) -> dict[str, Any]:
    n = len(data)
    if n <= MAX_PREVIEW * 2:
        head, tail = data, b""
    else:
        head, tail = data[:MAX_PREVIEW], data[-MAX_PREVIEW:]
    return {
        "size": n,
        "sha256": hashlib.sha256(data).hexdigest(),
        "head_hex": head.hex(" "),
        "tail_hex": tail.hex(" ") if tail else "",
        "truncated": n > MAX_PREVIEW * 2,
    }


class ExperimentRunner:
    def __init__(self, registry: Registry, results_dir: Path):
        self.registry = registry
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.history: list[dict[str, Any]] = []  # metadata index (memory+jsonl)
        self._load_history()

    # ---------- persistence ----------
    def _load_history(self) -> None:
        idx = self.results_dir / "history.jsonl"
        if idx.exists():
            for line in idx.read_text("utf-8", errors="replace").splitlines():
                try:
                    self.history.append(json.loads(line))
                except Exception:  # noqa: BLE001
                    pass

    def _append_history(self, entry: dict[str, Any]) -> None:
        with self.lock:
            self.history.append(entry)
            with open(self.results_dir / "history.jsonl", "a",
                      encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def save_result(self, rid: str, result: dict[str, Any],
                    recon: bytes | None = None) -> None:
        d = self.results_dir / rid
        d.mkdir(parents=True, exist_ok=True)
        (d / "result.json").write_text(
            json.dumps(result, indent=1), encoding="utf-8")
        if recon is not None:
            (d / "reconstructed.bin").write_bytes(recon)

    def get_result(self, rid: str) -> dict[str, Any] | None:
        p = self.results_dir / rid / "result.json"
        if p.exists():
            return json.loads(p.read_text("utf-8"))
        return None

    # ---------- phases ----------
    def analyze(self, formula_id: str, input_ref: dict, params: dict,
                data: bytes, label: str) -> dict[str, Any]:
        lf = self._formula(formula_id)
        caps = lf.capabilities()
        out: dict[str, Any] = {"input_label": label, "input_size": len(data),
                               "input_sha256": hashlib.sha256(data).hexdigest()}
        if not caps["supports_analysis"]:
            out["error"] = "formula does not support analysis"
            return out
        state, ms = call_analyze(lf, data, params)
        out.update({
            "state": state,
            "state_size": metrics.state_size(state),
            "encode_time_ms": round(ms, 3),
            "ratio": metrics.ratio(len(data), metrics.state_size(state)),
        })
        return out

    def reconstruct(self, formula_id: str, state: Any, size: int,
                    params: dict, expected: bytes | None) -> dict[str, Any]:
        lf = self._formula(formula_id)
        caps = lf.capabilities()
        if not caps["supports_reconstruction"]:
            return {"error": "formula does not support reconstruction"}
        data, ms, ops = call_reconstruct(lf, state, size, params)
        res: dict[str, Any] = {
            "_bytes": data,
            "generated_size": len(data),
            "reconstruct_time_ms": round(ms, 3),
            "reconstruct_ops": ops,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        if expected is not None:
            res["expected_sha256"] = hashlib.sha256(expected).hexdigest()
            res["comparison"] = metrics.compare(expected, data)
            res["output_preview"] = _preview(data)
        return res

    def read(self, formula_id: str, state: Any, offset: int, length: int,
             params: dict, expected: bytes | None) -> dict[str, Any]:
        lf = self._formula(formula_id)
        caps = lf.capabilities()
        if not caps["supports_random_access"]:
            return {"error": "formula does not support random access"}
        data, ms, ops = call_read(lf, state, offset, length, params)
        res: dict[str, Any] = {
            "offset": offset, "length": length,
            "generated_size": len(data),
            "read_time_ms": round(ms, 3),
            "states_evaluated": ops,
        }
        if expected is not None:
            res["expected_preview"] = _preview(expected)
            res["output_preview"] = _preview(data)
            res["comparison"] = metrics.compare(expected, data)
        return res

    # ---------- full experiment ----------
    def run_experiment(self, formula_id: str, input_ref: dict,
                       params: dict | None = None,
                       offset: int | None = None,
                       length: int | None = None,
                       data: bytes | None = None,
                       label: str | None = None) -> dict[str, Any]:
        from .samples import resolve_input  # local import avoids cycle
        params = params or {}
        rid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
        if data is None:
            data, label = resolve_input(self.registry.dir.parent / "samples",
                                        input_ref)
        label = label or "custom"
        base = {
            "id": rid,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "formula_id": formula_id,
            "sample": label,
            "parameters": params,
        }
        try:
            lf = self._formula(formula_id)
            base.update({"formula_name": lf.name,
                         "formula_version": lf.version})
        except Exception as e:  # noqa: BLE001
            return {**base, "status": "ERROR", "error": str(e)}

        result: dict[str, Any] = {**base, "input_size": len(data),
                                  "input_sha256":
                                      hashlib.sha256(data).hexdigest()}
        status_bits: list[str] = []
        t0 = time.perf_counter()
        recon_bytes: bytes | None = None

        # 1) analyze
        try:
            az = self.analyze(formula_id, input_ref, params, data, label)
            if "error" in az:
                result["analysis"] = az
                result["status"] = "UNSUPPORTED"
                result["total_time_ms"] = round((time.perf_counter()-t0)*1000, 1)
                self._finish(rid, result, None)
                return result
            state = az["state"]
            result["analysis"] = {k: v for k, v in az.items()
                                  if k != "input_sha256"}
            status_bits.append("ANALYZE ✓")
        except (FormulaError, TimeoutError) as e:
            self._fail(rid, result, status_bits, f"analyze: {e}", t0)
            return result
        except Exception as e:  # noqa: BLE001
            result["traceback"] = traceback.format_exc(limit=6)
            self._fail(rid, result, status_bits, f"analyze crash: {e}", t0)
            return result

        # 2) full reconstruction vs original
        caps = lf.capabilities()
        if caps["supports_reconstruction"]:
            try:
                rc = self.reconstruct(formula_id, state, len(data), params,
                                      data)
                result["reconstruction"] = {k: v for k, v in rc.items()
                                            if k != "_bytes"}
                recon_bytes = rc.get("_bytes")
                cmp = rc.get("comparison", {})
                if cmp.get("exact_match"):
                    status_bits.append("RECONSTRUCTION EXACT")
                else:
                    fm = cmp.get("first_mismatch_byte")
                    ber = cmp.get("bit_error_rate")
                    status_bits.append(
                        f"RECONSTRUCTION FAILED (first mismatch byte "
                        f"{fm}, BER {ber})")
            except NotImplementedError as e:
                result["reconstruction"] = {"error": f"not implemented: {e}"}
                status_bits.append("RECONSTRUCTION UNSUPPORTED")
            except Exception as e:  # noqa: BLE001
                result["reconstruction"] = {"error": f"{type(e).__name__}: {e}"}
                status_bits.append("RECONSTRUCTION ERROR")
        else:
            result["reconstruction"] = {"skipped": "capability not declared"}

        # 3) requested seek read
        if offset is not None and length is not None:
            try:
                validate_seek(len(data), offset, length)
                expected_win = data[offset:offset + length]
                rd = self.read(formula_id, state, offset, length, params,
                               expected_win)
                result["seek"] = rd
                if "error" in rd:
                    status_bits.append("RANDOM ACCESS UNSUPPORTED")
                elif rd["comparison"]["exact_match"]:
                    status_bits.append("SEEK MATCH")
                else:
                    status_bits.append(
                        f"SEEK MISMATCH (byte "
                        f"{rd['comparison']['first_mismatch_byte']})")
            except SeekError as e:
                result["seek"] = {"invalid_seek": True, "reason": str(e),
                                  "note": "INVALID SEEK is never reported "
                                          "as a match"}
                status_bits.append("INVALID SEEK")
            except Exception as e:  # noqa: BLE001
                result["seek"] = {"error": f"{type(e).__name__}: {e}"}
                status_bits.append("SEEK ERROR")

        # 4) true-random-access probe (if claimed)
        if caps["supports_random_access"] and len(data) >= 4 * SEEK_PROBE_LENGTH:
            try:
                probe = self.probe_random_access(formula_id, state, params,
                                                 len(data))
                result["random_access_probe"] = probe
                v = probe["verdict"]
                status_bits.append(
                    "TRUE RANDOM ACCESS" if v == "true" else
                    ("NOT TRUE RANDOM ACCESS" if v == "false" else
                     "RANDOM ACCESS UNKNOWN"))
            except Exception as e:  # noqa: BLE001
                result["random_access_probe"] = {"error": str(e)}

        result["total_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        result["status_bits"] = status_bits
        exact = any("EXACT" in s for s in status_bits)
        result["status"] = "EXACT" if exact else \
            ("FAILED" if any(("FAILED" in s or "MISMATCH" in s or
                              "ERROR" in s or "INVALID" in s)
                             for s in status_bits) else "PARTIAL")
        self._finish(rid, result, recon_bytes)
        return result

    def probe_random_access(self, formula_id: str, state: Any,
                            params: dict, size: int) -> dict[str, Any]:
        """Measure ops-per-read at increasing offsets. TRUE random access has
        roughly constant cost; sequential/simulated cost grows with offset."""
        offsets = [0, max(1, size // 4), max(1, size // 2),
                   max(1, size - SEEK_PROBE_LENGTH - 1)]
        offsets = sorted({o for o in offsets if 0 <= o <= size - SEEK_PROBE_LENGTH})
        samples = []
        for off in offsets:
            _, ms, ops = call_read(self._formula(formula_id), state, off,
                                   SEEK_PROBE_LENGTH, params)
            samples.append({"offset": off, "ops": ops, "ms": round(ms, 3)})
        first = samples[0]["ops"] if samples else 0
        last = samples[-1]["ops"] if samples else 0
        verdict = "unknown"
        reason = "insufficient data"
        if first > 0 and last > 0:
            growth = last / max(first, 1)
            if growth <= 2.0:
                verdict = "true"
                reason = (f"cost per read ~constant ({first}..{last} ops) "
                          "across offsets")
            elif growth >= 4.0:
                verdict = "false"
                reason = (f"cost grows with offset ({first} -> {last} ops): "
                          "reads simulate/scan from the start — this is NOT "
                          "true random access")
            else:
                verdict = "partial"
                reason = f"moderate growth ({first} -> {last} ops)"
        elif last > 0 and first == 0:
            verdict = "unknown"
            reason = "formula reports no op counts; cannot verify"
        return {
            "probe_length": SEEK_PROBE_LENGTH,
            "samples": samples,
            "verdict": verdict,
            "reason": reason,
            "declared_random_access":
                self._formula(formula_id).capabilities()["supports_random_access"],
        }

    # ---------- batch ----------
    def run_batch(self, formula_ids: list[str], input_ref: dict,
                  params: dict | None, on_progress=None) -> dict[str, Any]:
        """Runs one experiment per formula; one broken formula never aborts
        the batch. Returns compact rows for the matrix view."""
        from .samples import resolve_input
        data, label = resolve_input(self.registry.dir.parent / "samples",
                                    input_ref)
        rows = []
        n = len(formula_ids)
        for i, fid in enumerate(formula_ids):
            try:
                r = self.run_experiment(fid, input_ref, params,
                                        data=data, label=label)
                row = {
                    "formula_id": fid,
                    "formula_name": r.get("formula_name"),
                    "status": r.get("status"),
                    "status_bits": r.get("status_bits", []),
                    "error": r.get("error"),
                    "result_id": r.get("id"),
                    "state_size": r.get("analysis", {}).get("state_size"),
                    "ratio": r.get("analysis", {}).get("ratio"),
                    "exact_match": r.get("reconstruction", {})
                                   .get("comparison", {})
                                   .get("exact_match"),
                    "first_mismatch_byte": r.get("reconstruction", {})
                                           .get("comparison", {})
                                           .get("first_mismatch_byte"),
                    "bit_error_rate": r.get("reconstruction", {})
                                      .get("comparison", {})
                                      .get("bit_error_rate"),
                    "random_access_verdict": r.get("random_access_probe", {})
                                             .get("verdict"),
                }
            except Exception as e:  # noqa: BLE001 — isolate everything
                row = {"formula_id": fid, "status": "ERROR",
                       "error": f"{type(e).__name__}: {e}",
                       "exact_match": False}
            rows.append(row)
            if on_progress:
                on_progress({"done": i + 1, "total": n, "row": row})
        return {"sample": label, "input_size": len(data), "rows": rows}

    # ---------- helpers ----------
    def _formula(self, formula_id: str):
        key = str(formula_id).strip()
        if not key.isdigit():
            raise ValueError(f"formula id must be numeric, got {formula_id!r}")
        lf = self.registry.get(int(key))
        if lf is None:
            raise ValueError(f"formula {key} not loaded (rejected or missing)")
        return lf

    def _fail(self, rid, result, bits, msg, t0):
        result["status"] = "ERROR"
        result["error"] = msg
        result["status_bits"] = bits + [f"ERROR: {msg}"]
        result["total_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        self._finish(rid, result, None)

    def _finish(self, rid, result, recon):
        try:
            self.save_result(rid, result, recon)
        except Exception:  # noqa: BLE001 — never lose the response over disk
            pass
        caps = result.get("analysis", {})
        self._append_history({
            "id": rid, "time": result.get("time"),
            "formula_id": result.get("formula_id"),
            "formula_name": result.get("formula_name"),
            "sample": result.get("sample"),
            "status": result.get("status"),
            "input_size": result.get("input_size"),
            "state_size": caps.get("state_size"),
        })

    def history_list(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.lock:
            return list(reversed(self.history[-limit:]))
