"""Staged log uploads for the operator pipeline UI (Phase 57).

Files land under ``pipeline_ui.upload_dir`` (must resolve inside
``paths.raw_log_dir``) so the next ``ingest`` stage sees them via recursive
discovery. No job is started here — that remains ``POST /pipeline/jobs``.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any, Iterable

from src.config import pipeline_ui_settings
from src.ingestion.file_hash import CHUNK_SIZE, SourceFileDigest, hash_file_bytes

SKIP_UPLOAD_NAMES = frozenset({".gitkeep", ".DS_Store"})
DEMO_FIXTURE_REL = Path("tests") / "fixtures" / "logs" / "mixed_v3"
DEMO_ALLOWED_SUFFIXES = frozenset({".log", ".txt", ".json", ".jsonl", ".csv"})


class UploadError(Exception):
    """Operator-facing upload / corpus error."""

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def upload_dir_from_config(config: dict[str, Any]) -> Path:
    settings = pipeline_ui_settings(config)
    path = Path(str(settings["upload_dir"]))
    path.mkdir(parents=True, exist_ok=True)
    return path


def raw_dir_from_config(config: dict[str, Any]) -> Path:
    return Path(str(config["paths"]["raw_log_dir"]))


def sanitize_upload_basename(filename: str | None) -> str:
    """Return a safe basename; reject traversal and empty names."""
    if filename is None or not str(filename).strip():
        raise UploadError("filename is required", status_code=422)
    raw = str(filename).strip()
    if raw.startswith("/") or raw.startswith("\\") or (len(raw) >= 2 and raw[1] == ":"):
        raise UploadError("absolute upload paths are not allowed", status_code=400)
    parts = raw.replace("\\", "/").split("/")
    if any(part == ".." for part in parts):
        raise UploadError("path traversal is not allowed in upload names", status_code=400)
    name = Path(raw).name
    if not name or name in {".", ".."}:
        raise UploadError("invalid upload filename", status_code=400)
    if name.startswith("."):
        raise UploadError("hidden filenames are not allowed", status_code=400)
    if name in SKIP_UPLOAD_NAMES:
        raise UploadError(f"filename {name!r} is reserved", status_code=400)
    return name


def assert_allowed_suffix(name: str, allowed_suffixes: Iterable[str]) -> None:
    suffix = Path(name).suffix.lower()
    allowed = {s.lower() for s in allowed_suffixes}
    if suffix not in allowed:
        raise UploadError(
            f"suffix {suffix or '(none)'} is not allowed; "
            f"allowed: {', '.join(sorted(allowed))}",
            status_code=400,
        )


def unique_destination(directory: Path, basename: str) -> Path:
    """Pick ``basename`` or ``stem_N.suffix`` if the name already exists."""
    candidate = directory / basename
    if not candidate.exists():
        return candidate
    stem = Path(basename).stem
    suffix = Path(basename).suffix
    for index in range(1, 10_000):
        alt = directory / f"{stem}_{index}{suffix}"
        if not alt.exists():
            return alt
    raise UploadError("could not allocate a unique filename", status_code=500)


def file_item_from_path(path: Path, *, display_name: str | None = None) -> dict[str, Any]:
    digest = hash_file_bytes(path)
    return {
        "name": display_name or path.name,
        "size_bytes": digest.size_bytes,
        "sha256": digest.sha256,
        "modified_at": digest.mtime_utc.isoformat(),
    }


def list_staged_uploads(upload_dir: Path) -> list[dict[str, Any]]:
    if not upload_dir.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(upload_dir.iterdir()):
        if not path.is_file() or path.name in SKIP_UPLOAD_NAMES:
            continue
        items.append(file_item_from_path(path))
    return items


def list_existing_raw_top_level(raw_dir: Path) -> list[dict[str, Any]]:
    """Read-only listing of top-level files under ``raw_log_dir`` (not recursive)."""
    if not raw_dir.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(raw_dir.iterdir()):
        if not path.is_file() or path.name in SKIP_UPLOAD_NAMES:
            continue
        items.append(file_item_from_path(path))
    return items


def save_upload_stream(
    destination: Path,
    chunks: Iterable[bytes],
    *,
    max_bytes: int,
) -> SourceFileDigest:
    """Stream bytes to ``destination`` with a hard size cap; SHA-256 while writing."""
    hasher = hashlib.sha256()
    size_bytes = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("wb") as handle:
            for chunk in chunks:
                if not chunk:
                    continue
                size_bytes += len(chunk)
                if size_bytes > max_bytes:
                    raise UploadError(
                        f"file exceeds max_upload_bytes ({max_bytes})",
                        status_code=413,
                    )
                hasher.update(chunk)
                handle.write(chunk)
    except UploadError:
        destination.unlink(missing_ok=True)
        raise
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if size_bytes == 0:
        destination.unlink(missing_ok=True)
        raise UploadError("empty uploads are not allowed", status_code=400)
    # Re-stat for mtime consistency with hash_file_bytes.
    return hash_file_bytes(destination)


def iter_upload_file_chunks(upload_file: Any) -> Iterable[bytes]:
    while True:
        chunk = upload_file.file.read(CHUNK_SIZE)
        if not chunk:
            break
        yield chunk


def delete_staged_upload(upload_dir: Path, name: str) -> None:
    basename = sanitize_upload_basename(name)
    target = (upload_dir / basename).resolve()
    root = upload_dir.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise UploadError("path traversal is not allowed", status_code=400) from exc
    if not target.is_file():
        raise UploadError(f"staged file not found: {basename}", status_code=404)
    target.unlink()


def copy_demo_corpus(upload_dir: Path, *, code_root: Path | None = None) -> list[dict[str, Any]]:
    """Copy mixed_v3 demo log fixtures into the upload directory."""
    root = code_root or Path(__file__).resolve().parents[2]
    source_dir = root / DEMO_FIXTURE_REL
    if not source_dir.is_dir():
        raise UploadError(
            f"demo fixture directory missing: {source_dir}",
            status_code=500,
        )
    upload_dir.mkdir(parents=True, exist_ok=True)
    copied: list[dict[str, Any]] = []
    for path in sorted(source_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in DEMO_ALLOWED_SUFFIXES:
            continue
        dest = unique_destination(upload_dir, path.name)
        shutil.copy2(path, dest)
        copied.append(file_item_from_path(dest))
    if not copied:
        raise UploadError("demo fixture directory has no allowed log files", status_code=500)
    return copied
