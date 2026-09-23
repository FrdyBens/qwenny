"""Result export: one ZIP containing manifest.json, summary.json and per-
experiment folders (result.json + reconstructed.bin when available).

The ZIP is an experiment-result container only — it plays no part in any
mathematical reconstruction mechanism.
"""
from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any


def export_results(results_dir: Path, result_ids: list[str] | None = None,
                   history: list[dict[str, Any]] | None = None) -> bytes:
    results_dir = Path(results_dir)
    ids = result_ids
    if not ids:
        ids = sorted(p.name for p in results_dir.iterdir()
                     if p.is_dir() and (p / "result.json").exists())
    buf = io.BytesIO()
    stamp = time.strftime("%Y-%m-%d-%H%M%S")
    manifest = {
        "project": "ABC-INFINITY Formula Lab",
        "exported_at": stamp,
        "result_count": len(ids),
        "results": [],
    }
    summary_rows = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rid in ids:
            rdir = results_dir / rid
            rj = rdir / "result.json"
            if not rj.exists():
                continue
            try:
                res = json.loads(rj.read_text("utf-8"))
            except Exception:  # noqa: BLE001
                continue
            folder = f"result-{rid}"
            z.writestr(f"{folder}/result.json",
                       json.dumps(res, indent=1))
            binp = rdir / "reconstructed.bin"
            if binp.exists():
                z.write(binp, f"{folder}/reconstructed.bin")
            manifest["results"].append({
                "id": rid,
                "folder": folder,
                "formula_id": res.get("formula_id"),
                "formula_name": res.get("formula_name"),
                "sample": res.get("sample"),
                "status": res.get("status"),
                "has_reconstruction": binp.exists(),
            })
            summary_rows.append({
                "id": rid,
                "formula_id": res.get("formula_id"),
                "formula_name": res.get("formula_name"),
                "sample": res.get("sample"),
                "status": res.get("status"),
                "input_size": res.get("input_size"),
                "state_size": res.get("analysis", {}).get("state_size"),
                "ratio": res.get("analysis", {}).get("ratio"),
                "exact_match": res.get("reconstruction", {})
                               .get("comparison", {}).get("exact_match"),
                "first_mismatch_byte": res.get("reconstruction", {})
                                       .get("comparison",
                                            {}).get("first_mismatch_byte"),
                "bit_error_rate": res.get("reconstruction", {})
                                  .get("comparison", {}).get("bit_error_rate"),
                "random_access_verdict": res.get("random_access_probe", {})
                                         .get("verdict"),
            })
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        z.writestr("summary.json", json.dumps(summary_rows, indent=1))
        if history:
            z.writestr("history.jsonl",
                       "\n".join(json.dumps(h) for h in history))
    return buf.getvalue(), stamp
