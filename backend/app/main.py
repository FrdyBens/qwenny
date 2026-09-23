"""ABC-INFINITY Formula Lab — FastAPI application (stable API contract).

The TypeScript frontend only ever talks to these endpoints; it never imports
Python formulas. Adding formulas/samples requires no frontend change.

Endpoints
---------
GET  /api/health
GET  /api/formulas                  registry snapshot (count, cards, rejects)
GET  /api/formulas/{id}             one formula's metadata
GET  /api/samples                   recursive sample discovery
POST /api/samples/upload            add arbitrary file to samples/custom/
POST /api/analyze                   INPUT -> STATE (+ honest state size)
POST /api/reconstruct               STATE -> bytes (+ comparison vs original)
POST /api/read                      STATE + OFFSET/LENGTH -> window
                                    (strict seek validation first)
POST /api/experiment                full pipeline for one formula
POST /api/batch                     run many formulas, SSE progress
GET  /api/results/{id}              stored result JSON
GET  /api/results                   history index
POST /api/results/export            ZIP of results -> download
GET  /api/events                    SSE: registry reloads, batch progress
"""
from __future__ import annotations

import asyncio
import json
import queue
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from .export import export_results
from .registry import Registry, call_analyze, call_read, call_reconstruct
from .runner import ExperimentRunner, SeekError, validate_seek, _preview
from .samples import SampleError, list_samples, resolve_input

ROOT = Path(__file__).resolve().parents[2]   # abc-infinity/
FORMULAS_DIR = ROOT / "formulas"
SAMPLES_DIR = ROOT / "samples"
RESULTS_DIR = ROOT / "results"


class Bus:
    """Fan-out event channel for SSE (registry changes, batch progress)."""

    def __init__(self) -> None:
        self.subs: list[queue.Queue] = []
        self.lock = threading.Lock()

    def publish(self, event: dict) -> None:
        with self.lock:
            for q in self.subs:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=512)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)


def create_app(watch: bool = True) -> FastAPI:
    app = FastAPI(title="ABC-INFINITY Formula Lab", version="0.2.0")
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
        allow_headers=["*"])

    registry = Registry(FORMULAS_DIR)
    bus = Bus()
    registry.on_change = lambda e: bus.publish(
        {"type": "registry_changed", **e})
    runner = ExperimentRunner(registry, RESULTS_DIR)
    app.state.registry = registry
    app.state.runner = runner
    app.state.bus = bus
    registry.scan(notify=False)
    if watch:
        registry.watch()

    # ---------------- schemas ----------------
    class InputRef(BaseModel):
        kind: str = "sample"                       # sample | text | upload
        id: str | None = None                      # sample relative path
        text: str | None = None
        name: str | None = None
        data_b64: str | None = None
        persist: bool = True

    class FormulaReq(BaseModel):
        formula_id: str
        input: InputRef
        parameters: dict = Field(default_factory=dict)

    class ReadReq(FormulaReq):
        offset: int
        length: int

    class AnalyzeReq(FormulaReq):
        pass

    class ReconstructReq(BaseModel):
        formula_id: str
        input: InputRef
        state: object
        size: int
        parameters: dict = Field(default_factory=dict)

    class ExperimentReq(FormulaReq):
        offset: int | None = None
        length: int | None = None

    class BatchReq(BaseModel):
        formula_ids: list[str] | None = None       # default: all loaded
        input: InputRef
        parameters: dict = Field(default_factory=dict)
        per_formula_timeout_s: float = 30.0

    class ExportReq(BaseModel):
        result_ids: list[str] | None = None

    # ---------------- helpers ----------------
    def get_lf(fid: str):
        lf = registry.get(int(fid)) if str(fid).isdigit() else None
        if lf is None:
            raise HTTPException(404, f"formula {fid} not loaded "
                                     "(missing or rejected)")
        return lf

    def get_input(ref: InputRef):
        try:
            return resolve_input(SAMPLES_DIR, ref.model_dump())
        except SampleError as e:
            raise HTTPException(400, str(e)) from None

    # ---------------- static info ----------------
    @app.get("/api/health")
    def health():
        return {"ok": True, "project": "abc-infinity-formula-lab",
                "time": time.strftime("%Y-%m-%d %H:%M:%S")}

    @app.get("/api/formulas")
    def formulas():
        return registry.snapshot()

    @app.get("/api/formulas/{fid}")
    def formula_one(fid: str):
        lf = get_lf(fid)
        m = lf.mod
        src = lf.path.read_text("utf-8", errors="replace")
        return {**lf.meta(), "source": src,
                "analyze_timeout_s": getattr(m, "ANALYZE_TIMEOUT_S", 20)}

    @app.get("/api/samples")
    def samples():
        return {"samples": list_samples(SAMPLES_DIR)}

    @app.post("/api/samples/upload")
    async def upload(request: Request):
        body = await request.json()
        try:
            data, label = resolve_input(SAMPLES_DIR, {
                "kind": "upload", "name": body.get("name", "upload.bin"),
                "data_b64": body.get("data_b64", ""),
                "persist": body.get("persist", True)})
        except SampleError as e:
            raise HTTPException(400, str(e)) from None
        registry.scan()          # pick up any new sample immediately
        return {"ok": True, "saved_as": label, "size": len(data)}

    # ---------------- single operations ----------------
    @app.post("/api/analyze")
    def analyze(req: AnalyzeReq):
        lf = get_lf(req.formula_id)
        caps = lf.capabilities()
        if not caps["supports_analysis"]:
            raise HTTPException(400, "formula does not support analysis")
        data, label = get_input(req.input)
        try:
            state, ms = call_analyze(lf, data, req.parameters)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(422, f"analyze failed: {e}") from None
        from . import metrics
        return {"formula_id": req.formula_id, "input_label": label,
                "input_size": len(data), "state": state,
                "state_size": metrics.state_size(state),
                "encode_time_ms": round(ms, 3),
                "ratio": metrics.ratio(len(data), metrics.state_size(state))}

    @app.post("/api/read")
    def read(req: ReadReq):
        lf = get_lf(req.formula_id)
        caps = lf.capabilities()
        if not caps["supports_random_access"]:
            raise HTTPException(400,
                                "formula does not support random access")
        data, label = get_input(req.input)
        # STRICT seek validation BEFORE anything can produce empty slices.
        try:
            validate_seek(len(data), req.offset, req.length)
        except SeekError as e:
            return {"formula_id": req.formula_id, "input_label": label,
                    "invalid_seek": True, "reason": str(e),
                    "file_size": len(data), "offset": req.offset,
                    "length": req.length,
                    "note": "INVALID SEEK is never reported as a match"}
        try:
            state, _ms = call_analyze(lf, data, req.parameters)
            out, rms, ops = call_read(lf, state, req.offset, req.length,
                                      req.parameters)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(422, f"read failed: {e}") from None
        from . import metrics
        expected = data[req.offset:req.offset + req.length]
        return {"formula_id": req.formula_id, "input_label": label,
                "offset": req.offset, "length": req.length,
                "states_evaluated": ops, "read_time_ms": round(rms, 3),
                "expected_preview": _preview(expected),
                "output_preview": _preview(out),
                "comparison": metrics.compare(expected, out)}

    @app.post("/api/reconstruct")
    def reconstruct(req: ReconstructReq):
        lf = get_lf(req.formula_id)
        caps = lf.capabilities()
        if not caps["supports_reconstruction"]:
            raise HTTPException(400, "formula does not support reconstruction")
        try:
            out, rms, ops = call_reconstruct(lf, req.state, req.size,
                                             req.parameters)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(422, f"reconstruct failed: {e}") from None
        res = {"formula_id": req.formula_id, "generated_size": len(out),
               "reconstruct_time_ms": round(rms, 3), "ops": ops,
               "output_preview": _preview(out)}
        # optional verification against original if an input ref is given
        if req.input.kind in ("sample", "text"):
            try:
                data, _ = get_input(req.input)
                from . import metrics
                res["comparison"] = metrics.compare(data[:req.size], out)
            except HTTPException:
                pass
        return res

    @app.post("/api/experiment")
    def experiment(req: ExperimentReq):
        r = runner.run_experiment(req.formula_id, req.input.model_dump(),
                                  req.parameters, req.offset, req.length)
        return r

    # ---------------- batch (background thread + SSE progress) ----------------
    @app.post("/api/batch")
    def batch(req: BatchReq):
        ids = req.formula_ids or [f["id"] for f in
                                  registry.snapshot()["formulas"]]
        if not ids:
            raise HTTPException(400, "no formulas loaded")
        batch_id = f"batch-{int(time.time()*1000)}"
        state = {"finished": False, "result": None, "error": None,
                 "done": 0, "total": len(ids), "rows": []}
        _BATCHES[batch_id] = state

        def worker():
            def prog(p):
                state["done"] = p["done"]
                state["rows"].append(p["row"])
                bus.publish({"type": "batch_progress", "done": p["done"],
                             "total": p["total"],
                             "formula_id": p["row"]["formula_id"],
                             "status": p["row"]["status"], "batch": batch_id})
            try:
                res = runner.run_batch(ids, req.input.model_dump(),
                                       req.parameters, on_progress=prog)
                state["result"] = res
            except Exception as e:  # noqa: BLE001
                state["error"] = f"{type(e).__name__}: {e}"
            finally:
                state["finished"] = True
                bus.publish({"type": "batch_done", "batch": batch_id})

        threading.Thread(target=worker, daemon=True).start()
        return {"batch_id": batch_id, "total": len(ids),
                "poll": f"/api/batch/{batch_id}"}

    @app.get("/api/batch/{batch_id}")
    def batch_status(batch_id: str):
        st = _BATCHES.get(batch_id)
        if st is None:
            raise HTTPException(404, "unknown batch")
        out = {k: v for k, v in st.items() if k != "result"}
        out["has_result"] = st["result"] is not None
        return out

    @app.get("/api/history")
    def history(limit: int = 200):
        return {"history": runner.history_list(limit)}

    @app.get("/api/results/{rid}")
    def result(rid: str):
        r = runner.get_result(rid)
        if r is None:
            raise HTTPException(404, "no such result")
        return r

    @app.post("/api/results/export")
    def export(req: ExportReq):
        blob, stamp = export_results(RESULTS_DIR, req.result_ids,
                                     runner.history_list(1000))
        fn = f"abc-infinity-results-{stamp}.zip"
        (RESULTS_DIR / fn).write_bytes(blob)
        return Response(content=blob, media_type="application/zip",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{fn}"'})

    # ---------------- SSE ----------------
    @app.get("/api/events")
    async def events(request: Request):
        q = bus.subscribe()

        async def gen():
            try:
                yield "data: " + json.dumps({"type": "hello"}) + "\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        ev = q.get_nowait()
                        yield "data: " + json.dumps(ev) + "\n\n"
                    except queue.Empty:
                        await asyncio.sleep(0.4)
            finally:
                bus.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache"})

    return app


_BATCHES: dict[str, dict] = {}
