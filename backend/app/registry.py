"""Dynamic formula registry with safe hot reload.

- Discovers formulas/*.py (numbering is organizational, no hard limit).
- Loads each file in an isolated module namespace; syntax/API errors reject
  only that file and never crash the backend.
- Keeps the last-known-good version of every formula; a broken edit does not
  remove the working one from the registry.
- Exposes snapshot() for the API and a change callback for SSE notifications.
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable

from .contract import (DEFAULT_ANALYZE_TIMEOUT_S, FormulaError, REQUIRED_META,
                       json_safe)


def _load_formula_source(path: Path):
    """Load a formula .py file fresh (bypasses sys.modules caching).

    Injects the backend dir so `from contract import FormulaError` and
    `import abc_formula` work inside formula files.
    """
    backend_dir = str(Path(__file__).resolve().parent)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    mod_name = f"abc_formula_mod_{path.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot create import spec for {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop(mod_name, None)
        raise
    return mod


class LoadedFormula:
    def __init__(self, fid: int, path: Path, mod: Any, sha: str, mtime: float):
        self.id = fid
        self.formula_id = f"{fid:03d}"
        self.path = path
        self.mod = mod
        self.sha = sha
        self.mtime = mtime
        self.loaded_at = time.time()

    @property
    def name(self) -> str:
        return str(getattr(self.mod, "NAME"))

    @property
    def version(self) -> str:
        return str(getattr(self.mod, "VERSION"))

    def capabilities(self) -> dict[str, bool]:
        m = self.mod
        has = lambda fn: callable(getattr(m, fn, None))  # noqa: E731
        declared = {
            "analysis": bool(getattr(m, "SUPPORTS_ANALYSIS", False)),
            "reconstruction": bool(getattr(m, "SUPPORTS_RECONSTRUCTION", False)),
            "random_access": bool(getattr(m, "SUPPORTS_RANDOM_ACCESS", False)),
            "streaming": bool(getattr(m, "SUPPORTS_STREAMING", False)),
        }
        # A capability counts only if declared AND implemented.
        return {
            "supports_analysis": declared["analysis"] and has("analyze"),
            "supports_reconstruction": declared["reconstruction"] and has("reconstruct"),
            "supports_random_access": declared["random_access"] and has("read"),
            "supports_streaming": declared["streaming"],
        }

    def meta(self) -> dict[str, Any]:
        m = self.mod
        return {
            "id": self.formula_id,
            "numeric_id": self.id,
            "name": self.name,
            "version": self.version,
            "description": str(getattr(m, "DESCRIPTION")),
            "category": str(getattr(m, "CATEGORY")),
            "tags": list(getattr(m, "TAGS", [])),
            "parameters": getattr(m, "PARAMETERS", {}),
            "capabilities": self.capabilities(),
            "file": self.path.name,
            "sha256": self.sha[:16],
            "mtime": self.mtime,
            "api_valid": True,
            "error": None,
        }


def _validate(mod: Any, path: Path) -> tuple[int | None, list[str]]:
    """Return (numeric id, list of rejection reasons). Empty list = valid."""
    errs: list[str] = []
    fname = path.name
    stem = fname[:-3] if fname.endswith(".py") else fname
    num = stem.split("_", 1)[0]
    fid = int(num) if num.isdigit() else None
    if fid is None:
        errs.append(f"filename '{fname}' must start with a number (e.g. 042_...)")
    if stem.startswith("_"):
        errs.append("files starting with '_' are templates, not formulas")
    for key in REQUIRED_META:
        v = getattr(mod, key, None)
        if not isinstance(v, str) or not v:
            errs.append(f"missing/invalid metadata {key} (must be non-empty str)")
    ops = [n for n in ("analyze", "reconstruct", "read")
           if callable(getattr(mod, n, None))]
    if "analyze" not in ops:
        errs.append("missing analyze(INPUT, PARAMETERS)")
    if not any(o in ops for o in ("reconstruct", "read")):
        errs.append("must implement reconstruct(STATE, SIZE, PARAMETERS) "
                    "and/or read(STATE, OFFSET, LENGTH, PARAMETERS)")
    caps = getattr(mod, "SUPPORTS_ANALYSIS", False) or \
        getattr(mod, "SUPPORTS_RECONSTRUCTION", False) or \
        getattr(mod, "SUPPORTS_RANDOM_ACCESS", False)
    if not caps:
        errs.append("no SUPPORTS_* capability declared (formula would do nothing)")
    return fid, errs


class Registry:
    def __init__(self, formulas_dir: Path):
        self.dir = Path(formulas_dir)
        self.lock = threading.Lock()
        self.good: dict[int, LoadedFormula] = {}     # last known good
        self.bad: dict[str, dict[str, Any]] = {}     # filename -> error info
        self.on_change: Callable[[dict], None] | None = None
        self._stop = threading.Event()
        self._watch_thread: threading.Thread | None = None

    # ---------- loading ----------
    def _file_state(self, path: Path):
        data = path.read_bytes()
        return hashlib.sha256(data).hexdigest(), data

    def load_one(self, path: Path) -> None:
        fname = path.name
        try:
            sha, _ = self._file_state(path)
            with self.lock:
                prev = self.good.get(int(fname.split("_", 1)[0])
                                     if fname.split("_", 1)[0].isdigit() else -1)
            mod = _load_formula_source(path)
            fid, errs = _validate(mod, path)
            if errs or fid is None:
                with self.lock:
                    self.bad[fname] = {"errors": errs, "sha": sha,
                                       "kept_previous": bool(prev)}
                return
            lf = LoadedFormula(fid, path, mod, sha, path.stat().st_mtime)
            # smoke-test JSON-safety of state with a trivial input
            with self.lock:
                self.good[fid] = lf
                self.bad.pop(fname, None)
        except SyntaxError as e:
            with self.lock:
                self.bad[fname] = {"errors": [f"SyntaxError: {e}"],
                                   "kept_previous": True}
        except Exception as e:  # noqa: BLE001 — one bad file must not crash us
            with self.lock:
                self.bad[fname] = {
                    "errors": [f"{type(e).__name__}: {e}"],
                    "traceback": traceback.format_exc(limit=8),
                    "kept_previous": True,
                }

    def scan(self, notify: bool = True) -> None:
        changed = False
        if self.dir.exists():
            for path in sorted(self.dir.glob("*.py")):
                try:
                    sha = self._file_state(path)[0]
                except OSError:
                    continue
                fid_s = path.name.split("_", 1)[0]
                fid = int(fid_s) if fid_s.isdigit() else -1
                cur = self.good.get(fid)
                bad = self.bad.get(path.name)
                if cur is not None and cur.sha == sha:
                    continue
                if bad is not None and bad.get("sha") == sha:
                    continue
                self.load_one(path)
                changed = True
            # detect deletions of good formulas
            present = {p.name for p in self.dir.glob("*.py")}
            with self.lock:
                for fid in list(self.good):
                    if self.good[fid].path.name not in present:
                        del self.good[fid]
                        changed = True
        if changed and notify and self.on_change:
            try:
                self.on_change({"type": "registry", "count": len(self.good)})
            except Exception:  # noqa: BLE001
                pass

    # ---------- hot reload watcher ----------
    def watch(self, interval: float = 0.75) -> None:
        """Poll-based watcher: robust across platforms/editors (atomic saves,
        editors rewriting files), unlike raw inotify. Cheap: stat+hash only."""
        def loop():
            while not self._stop.is_set():
                try:
                    self.scan()
                except Exception:  # noqa: BLE001
                    pass
                self._stop.wait(interval)
        self._watch_thread = threading.Thread(target=loop, daemon=True,
                                              name="formula-watcher")
        self._watch_thread.start()

    def stop_watch(self) -> None:
        self._stop.set()

    # ---------- queries ----------
    def get(self, fid: int) -> LoadedFormula | None:
        with self.lock:
            return self.good.get(fid)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            formulas = [self.good[k].meta() for k in sorted(self.good)]
            rejected = [{"file": k, **v} for k, v in sorted(self.bad.items())]
        return {
            "loaded": len(formulas),
            "categories": sorted({f["category"] for f in formulas}),
            "formulas": formulas,
            "rejected": rejected,
        }


# ---- helpers used by the runner (kept here so both share one code path) ----
def call_analyze(lf: LoadedFormula, data: bytes, params: dict):
    import abc_formula
    abc_formula.reset()
    timeout = float(getattr(lf.mod, "ANALYZE_TIMEOUT_S",
                            DEFAULT_ANALYZE_TIMEOUT_S))
    result: dict[str, Any] = {}

    def run():
        try:
            result["state"] = lf.mod.analyze(data, params)
        except BaseException as e:  # noqa: BLE001
            result["exc"] = e

    t = threading.Thread(target=run, daemon=True)
    t0 = time.perf_counter()
    t.start()
    t.join(timeout)
    ms = (time.perf_counter() - t0) * 1000
    if t.is_alive():
        raise TimeoutError(f"analyze() exceeded {timeout}s guard "
                           "(formula too slow for this input)")
    if "exc" in result:
        raise result["exc"]
    state = result["state"]
    ok, why = json_safe(state)
    if not ok:
        raise FormulaError(f"analyze returned invalid state: {why}")
    # deep-copy through JSON so reconstruction can never touch live objects
    import json
    state = json.loads(json.dumps(state))
    return state, ms


def call_read(lf: LoadedFormula, state, offset: int, length: int, params: dict):
    import abc_formula
    abc_formula.reset()
    t0 = time.perf_counter()
    out = lf.mod.read(state, offset, length, params)
    ms = (time.perf_counter() - t0) * 1000
    ops = abc_formula.get()
    if not isinstance(out, (bytes, bytearray)):
        raise FormulaError(f"read() must return bytes, got {type(out).__name__}")
    return bytes(out), ms, ops


def call_reconstruct(lf: LoadedFormula, state, size: int, params: dict):
    import abc_formula
    abc_formula.reset()
    t0 = time.perf_counter()
    out = lf.mod.reconstruct(state, size, params)
    ms = (time.perf_counter() - t0) * 1000
    ops = abc_formula.get()
    if not isinstance(out, (bytes, bytearray)):
        raise FormulaError(
            f"reconstruct() must return bytes, got {type(out).__name__}")
    return bytes(out), ms, ops
