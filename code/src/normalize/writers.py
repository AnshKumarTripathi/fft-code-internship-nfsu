"""Output paths, manifest.jsonl, and normalize dead-letter JSONL."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

SKIP_CLEAR_NAMES = frozenset({".gitkeep"})


def normalize_output_dir(settings: dict[str, Any]) -> Path:
    return Path(str(settings["output_dir"]))


def normalize_dead_letter_dir(settings: dict[str, Any]) -> Path:
    """Sibling of output_dir: ``…/normalize_dead_letter``."""
    return normalize_output_dir(settings).resolve().parent / "normalize_dead_letter"


def clear_directory(path: Path) -> None:
    if path.exists():
        for child in list(path.iterdir()):
            if child.name in SKIP_CLEAR_NAMES:
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink(missing_ok=True)
    path.mkdir(parents=True, exist_ok=True)


def clear_normalize_output(settings: dict[str, Any]) -> Path:
    out = normalize_output_dir(settings)
    clear_directory(out)
    return out


def clear_normalize_dead_letter(settings: dict[str, Any]) -> Path:
    dead = normalize_dead_letter_dir(settings)
    clear_directory(dead)
    return dead


def ensure_normalize_dirs(settings: dict[str, Any]) -> None:
    normalize_output_dir(settings).mkdir(parents=True, exist_ok=True)
    normalize_dead_letter_dir(settings).mkdir(parents=True, exist_ok=True)


def copy_passthrough(source: Path, destination: Path) -> int:
    """Copy file for custody (no hardlink). Return bytes written."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination.stat().st_size


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")


def manifest_path(output_dir: Path) -> Path:
    return output_dir / "manifest.jsonl"


def dead_letter_path(settings: dict[str, Any]) -> Path:
    return normalize_dead_letter_dir(settings) / "dead-letter.jsonl"


def write_manifest_row(
    output_dir: Path,
    *,
    source_path: str,
    output_path: str,
    converter: str,
    source_sha256: str,
    output_sha256: str,
    bytes_in: int,
    bytes_out: int,
) -> None:
    append_jsonl(
        manifest_path(output_dir),
        {
            "source_path": source_path,
            "output_path": output_path,
            "converter": converter,
            "source_sha256": source_sha256,
            "output_sha256": output_sha256,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
        },
    )


def write_dead_letter_row(
    settings: dict[str, Any],
    *,
    source_path: str,
    reason: str,
    converter_tried: str | None,
    message: str | None = None,
) -> None:
    payload: dict[str, Any] = {
        "source_path": source_path,
        "reason": reason,
        "converter_tried": converter_tried,
    }
    if message:
        payload["message"] = message
    append_jsonl(dead_letter_path(settings), payload)
