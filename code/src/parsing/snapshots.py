"""Drain3 parser snapshots under ``baseline_dir/snapshots/parse/`` (R5)."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.ingestion.file_hash import hash_file_bytes
from src.parsing.drain3_wrapper import DRAIN3_STATE_FILENAME, drain3_state_path

EMPTY_PARSER_SNAPSHOT_ID = "empty"


class ParserSnapshotError(Exception):
    """Raised when a named snapshot cannot be loaded."""


def parser_snapshot_state_path(baseline_dir: str | Path, snapshot_id: str) -> Path:
    return (
        Path(baseline_dir)
        / "snapshots"
        / "parse"
        / snapshot_id
        / DRAIN3_STATE_FILENAME
    )


def prepare_parser_state(
    baseline_dir: str | Path,
    *,
    mode: str,
    start_empty: bool,
    snapshot_id: str | None,
) -> str:
    """Reset live ``drain3_state.bin`` and return the starting snapshot id.

    ``reuse_snapshot`` copies a frozen file over the live state.
    ``train_and_snapshot`` optionally starts empty (named), else continues live.
    """
    live = drain3_state_path(baseline_dir)
    live.parent.mkdir(parents=True, exist_ok=True)

    if mode == "reuse_snapshot":
        if not snapshot_id:
            raise ParserSnapshotError(
                "parse.snapshot_id is required when parse.mode is reuse_snapshot"
            )
        if snapshot_id == EMPTY_PARSER_SNAPSHOT_ID:
            if live.is_file():
                live.unlink()
            return EMPTY_PARSER_SNAPSHOT_ID
        source = parser_snapshot_state_path(baseline_dir, snapshot_id)
        if not source.is_file():
            raise ParserSnapshotError(f"parser snapshot not found: {source}")
        shutil.copy2(source, live)
        return snapshot_id

    if start_empty and live.is_file():
        live.unlink()
    if start_empty or not live.is_file():
        return EMPTY_PARSER_SNAPSHOT_ID
    return hash_file_bytes(live).sha256


def save_parser_snapshot(baseline_dir: str | Path) -> str | None:
    """Copy live Drain3 state to a content-addressed snapshot dir. None if empty."""
    live = drain3_state_path(baseline_dir)
    if not live.is_file():
        return None
    snapshot_id = hash_file_bytes(live).sha256
    dest = parser_snapshot_state_path(baseline_dir, snapshot_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(live, dest)
    return snapshot_id
