"""Line-safe splitter for oversized text logs (Phase 88).

Soft targets may be slightly exceeded by one line so a cut never lands mid-line.
``byte_start`` is inclusive; ``byte_end`` is exclusive (Python slice semantics).
``line_start`` / ``line_end`` are 1-based inclusive line numbers in the source.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from src.ingestion.file_hash import hash_file_bytes
from src.ingestion.sharding.manifest import (
    ShardManifestRecord,
    write_manifest,
)

logger = logging.getLogger(__name__)

READ_CHUNK = 1024 * 1024


class ShardError(Exception):
    """Raised when a line-safe split cannot complete."""


@dataclass(frozen=True)
class ShardSplitResult:
    run_id: str
    run_dir: Path
    source_path: Path
    source_sha256: str
    source_size_bytes: int
    shard_count: int
    manifest_path: Path
    records: list[ShardManifestRecord]


def _shard_filename(stem: str, suffix: str, index: int) -> str:
    safe_stem = stem or "shard"
    return f"{safe_stem}.shard{index:05d}{suffix}"


def _should_rotate(
    *,
    bytes_in_shard: int,
    lines_in_shard: int,
    target_shard_bytes: int | None,
    target_shard_lines: int | None,
) -> bool:
    if bytes_in_shard <= 0 and lines_in_shard <= 0:
        return False
    if target_shard_bytes is not None and bytes_in_shard >= target_shard_bytes:
        return True
    if target_shard_lines is not None and lines_in_shard >= target_shard_lines:
        return True
    return False


def split_log_file(
    input_path: Path | str,
    *,
    output_dir: Path | str,
    target_shard_bytes: int | None = 1_073_741_824,
    target_shard_lines: int | None = None,
    max_shards: int = 500,
    run_id: str | None = None,
) -> ShardSplitResult:
    """Split ``input_path`` into line-safe shards under ``output_dir/<run_id>/``."""
    source = Path(input_path)
    if not source.is_file():
        raise ShardError(f"input is not a file: {source}")
    if source.stat().st_size == 0:
        raise ShardError(f"refusing empty input: {source}")
    if target_shard_bytes is None and target_shard_lines is None:
        raise ShardError("require target_shard_bytes and/or target_shard_lines")
    if target_shard_bytes is not None and target_shard_bytes < 1:
        raise ShardError("target_shard_bytes must be a positive integer")
    if target_shard_lines is not None and target_shard_lines < 1:
        raise ShardError("target_shard_lines must be a positive integer")
    if max_shards < 1:
        raise ShardError("max_shards must be a positive integer")

    digest = hash_file_bytes(source)
    split_run_id = (run_id or uuid.uuid4().hex).strip()
    if not split_run_id:
        raise ShardError("run_id must be a non-empty string")

    root = Path(output_dir)
    run_dir = root / split_run_id
    if run_dir.exists() and any(run_dir.iterdir()):
        raise ShardError(f"shard run directory already exists and is not empty: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)

    stem = source.stem
    suffix = source.suffix
    records: list[ShardManifestRecord] = []

    shard_index = 0
    shard_path: Path | None = None
    shard_handle = None
    bytes_in_shard = 0
    lines_in_shard = 0
    byte_cursor = 0
    shard_byte_start = 0
    shard_line_start = 1
    line_number = 0
    pending = b""

    def _open_shard(index: int) -> None:
        nonlocal shard_path, shard_handle, bytes_in_shard, lines_in_shard
        nonlocal shard_byte_start, shard_line_start
        if index >= max_shards:
            raise ShardError(
                f"max_shards={max_shards} exceeded while splitting {source}"
            )
        shard_path = run_dir / _shard_filename(stem, suffix, index)
        shard_handle = shard_path.open("wb")
        bytes_in_shard = 0
        lines_in_shard = 0
        shard_byte_start = byte_cursor
        shard_line_start = line_number + 1

    def _close_shard() -> None:
        nonlocal shard_handle, shard_index
        if shard_handle is None or shard_path is None:
            return
        shard_handle.close()
        shard_handle = None
        shard_digest = hash_file_bytes(shard_path)
        line_end = line_number if lines_in_shard > 0 else shard_line_start - 1
        records.append(
            ShardManifestRecord(
                run_id=split_run_id,
                source_path=str(source.resolve()),
                source_sha256=digest.sha256,
                source_size_bytes=digest.size_bytes,
                shard_index=shard_index,
                shard_path=str(shard_path.resolve()),
                shard_sha256=shard_digest.sha256,
                shard_size_bytes=shard_digest.size_bytes,
                byte_start=shard_byte_start,
                byte_end=byte_cursor,
                line_start=shard_line_start,
                line_end=line_end,
            )
        )
        shard_index += 1

    try:
        _open_shard(0)
        assert shard_handle is not None

        with source.open("rb") as source_handle:
            while True:
                chunk = source_handle.read(READ_CHUNK)
                if not chunk:
                    break
                pending += chunk
                while True:
                    newline_at = pending.find(b"\n")
                    if newline_at < 0:
                        break
                    line = pending[: newline_at + 1]
                    pending = pending[newline_at + 1 :]
                    if _should_rotate(
                        bytes_in_shard=bytes_in_shard,
                        lines_in_shard=lines_in_shard,
                        target_shard_bytes=target_shard_bytes,
                        target_shard_lines=target_shard_lines,
                    ):
                        _close_shard()
                        _open_shard(shard_index)
                        assert shard_handle is not None
                    shard_handle.write(line)
                    bytes_in_shard += len(line)
                    byte_cursor += len(line)
                    lines_in_shard += 1
                    line_number += 1

            if pending:
                if _should_rotate(
                    bytes_in_shard=bytes_in_shard,
                    lines_in_shard=lines_in_shard,
                    target_shard_bytes=target_shard_bytes,
                    target_shard_lines=target_shard_lines,
                ):
                    _close_shard()
                    _open_shard(shard_index)
                    assert shard_handle is not None
                shard_handle.write(pending)
                bytes_in_shard += len(pending)
                byte_cursor += len(pending)
                lines_in_shard += 1
                line_number += 1
                pending = b""

        _close_shard()
    except Exception:
        if shard_handle is not None:
            shard_handle.close()
        raise

    if byte_cursor != digest.size_bytes:
        raise ShardError(
            f"byte accounting mismatch for {source}: "
            f"wrote {byte_cursor}, source size {digest.size_bytes}"
        )

    manifest = write_manifest(run_dir, records)
    logger.info(
        "shard-split complete run_id=%s shards=%d source=%s",
        split_run_id,
        len(records),
        source,
    )
    return ShardSplitResult(
        run_id=split_run_id,
        run_dir=run_dir,
        source_path=source.resolve(),
        source_sha256=digest.sha256,
        source_size_bytes=digest.size_bytes,
        shard_count=len(records),
        manifest_path=manifest,
        records=records,
    )
