"""Sample discovery + safe input resolution.

Scans samples/ recursively (subdirectories supported). No file-type
restrictions: everything is arbitrary bytes. SHA-256 is computed for
identification/verification ONLY — inputs to formulas are raw bytes.

Uploads go to samples/custom/ with a sanitized name; existing files are not
silently overwritten (a suffix is added).
"""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # guard, not a math restriction


class SampleError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _describe(path: Path, root: Path) -> dict[str, Any]:
    st = path.stat()
    rel = path.relative_to(root).as_posix()
    return {
        "id": rel,
        "filename": path.name,
        "size": st.st_size,
        "sha256": sha256_file(path),
        "mtime": st.st_mtime,
        "modified": time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(st.st_mtime)),
        "type": path.suffix.lstrip(".").lower() or "bin",
    }


def list_samples(root: Path) -> list[dict[str, Any]]:
    root = Path(root)
    out = []
    if root.exists():
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                out.append(_describe(p, root))
    return out


def resolve_input(root: Path, ref: dict[str, Any]) -> tuple[bytes, str]:
    """ref: {"kind":"sample","id":...} | {"kind":"text","text":...}
       | {"kind":"upload","name":...,"data_b64":...}
    Returns (INPUT bytes, human label). Path traversal is rejected."""
    kind = ref.get("kind")
    if kind == "text":
        t = ref.get("text")
        if not isinstance(t, str):
            raise SampleError("text input missing 'text'")
        return t.encode("utf-8"), f"text:{len(t.encode('utf-8'))}B"
    if kind == "sample":
        sid = ref.get("id", "")
        target = (Path(root) / sid).resolve()
        root_r = Path(root).resolve()
        if not target.is_relative_to(root_r) or not target.is_file():
            raise SampleError(f"invalid sample id: {sid!r}")
        return target.read_bytes(), sid
    if kind == "upload":
        import base64
        name = sanitize_name(ref.get("name", "upload.bin"))
        b64 = ref.get("data_b64", "")
        try:
            data = base64.b64decode(b64, validate=True)
        except Exception as e:  # noqa: BLE001
            raise SampleError(f"bad upload payload: {e}") from None
        if len(data) > MAX_UPLOAD_BYTES:
            raise SampleError("upload too large")
        persist = bool(ref.get("persist", True))
        saved = ""
        if persist:
            dest_dir = Path(root) / "custom"
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = unique_path(dest_dir / name)
            dest.write_bytes(data)
            saved = dest.relative_to(Path(root)).as_posix()
        return data, f"upload:{name}" + (f" -> {saved}" if saved else "")
    raise SampleError(f"unknown input kind: {kind!r}")


def sanitize_name(name: str) -> str:
    name = Path(name).name  # strip any directories
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip() or "upload.bin"
    return name[:120]


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suf = path.stem, path.suffix
    i = 1
    while True:
        cand = path.with_name(f"{stem}-{i}{suf}")
        if not cand.exists():
            return cand
        i += 1
