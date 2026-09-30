"""Provenance manifest for line-safe shard splits (Phase 88)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ShardManifestRecord:
    """One shard row; maps staged byte/line ranges back to the source file."""

    run_id: str
    source_path: str
    source_sha256: str
    source_size_bytes: int
    shard_index: int
    shard_path: str
    shard_sha256: str
    shard_size_bytes: int
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> ShardManifestRecord:
        return cls(
            run_id=str(row["run_id"]),
            source_path=str(row["source_path"]),
            source_sha256=str(row["source_sha256"]),
            source_size_bytes=int(row["source_size_bytes"]),
            shard_index=int(row["shard_index"]),
            shard_path=str(row["shard_path"]),
            shard_sha256=str(row["shard_sha256"]),
            shard_size_bytes=int(row["shard_size_bytes"]),
            byte_start=int(row["byte_start"]),
            byte_end=int(row["byte_end"]),
            line_start=int(row["line_start"]),
            line_end=int(row["line_end"]),
        )


def manifest_path(run_dir: Path) -> Path:
    return run_dir / "manifest.jsonl"


def write_manifest(run_dir: Path, records: list[ShardManifestRecord]) -> Path:
    """Write ``manifest.jsonl`` (one JSON object per shard). Overwrites."""
    path = manifest_path(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
    return path


def read_manifest(path: Path) -> list[ShardManifestRecord]:
    """Load manifest.jsonl; empty file → empty list."""
    if not path.is_file():
        raise FileNotFoundError(f"shard manifest not found: {path}")
    records: list[ShardManifestRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON in shard manifest {path} line {line_no}"
                ) from exc
            if not isinstance(row, dict):
                raise ValueError(
                    f"shard manifest {path} line {line_no} must be a JSON object"
                )
            records.append(ShardManifestRecord.from_dict(row))
    return records
