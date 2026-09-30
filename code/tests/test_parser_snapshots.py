"""Unit tests for Drain3 parser snapshot prepare/save."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.parsing.drain3_wrapper import drain3_state_path
from src.parsing.snapshots import (
    EMPTY_PARSER_SNAPSHOT_ID,
    ParserSnapshotError,
    prepare_parser_state,
    save_parser_snapshot,
)


def test_start_empty_is_named_empty(tmp_path: Path) -> None:
    baseline = tmp_path / "baselines"
    live = drain3_state_path(baseline)
    live.parent.mkdir(parents=True)
    live.write_bytes(b"leftover-miner-state")
    snapshot_id = prepare_parser_state(
        baseline, mode="train_and_snapshot", start_empty=True, snapshot_id=None
    )
    assert snapshot_id == EMPTY_PARSER_SNAPSHOT_ID
    assert not live.is_file()


def test_reuse_empty_unlinks_live(tmp_path: Path) -> None:
    baseline = tmp_path / "baselines"
    live = drain3_state_path(baseline)
    live.parent.mkdir(parents=True)
    live.write_bytes(b"leftover")
    snapshot_id = prepare_parser_state(
        baseline,
        mode="reuse_snapshot",
        start_empty=False,
        snapshot_id=EMPTY_PARSER_SNAPSHOT_ID,
    )
    assert snapshot_id == EMPTY_PARSER_SNAPSHOT_ID
    assert not live.is_file()


def test_reuse_missing_snapshot_raises(tmp_path: Path) -> None:
    with pytest.raises(ParserSnapshotError, match="not found"):
        prepare_parser_state(
            tmp_path / "baselines",
            mode="reuse_snapshot",
            start_empty=False,
            snapshot_id="missing-id",
        )


def test_save_parser_snapshot_is_content_addressed(tmp_path: Path) -> None:
    baseline = tmp_path / "baselines"
    live = drain3_state_path(baseline)
    live.parent.mkdir(parents=True)
    live.write_bytes(b"drain3-bytes")
    snapshot_id = save_parser_snapshot(baseline)
    assert snapshot_id
    frozen = (
        baseline / "snapshots" / "parse" / snapshot_id / "drain3_state.bin"
    )
    assert frozen.is_file()
    assert frozen.read_bytes() == b"drain3-bytes"

    prepare_parser_state(
        baseline, mode="train_and_snapshot", start_empty=True, snapshot_id=None
    )
    assert not live.is_file()
    restored = prepare_parser_state(
        baseline,
        mode="reuse_snapshot",
        start_empty=False,
        snapshot_id=snapshot_id,
    )
    assert restored == snapshot_id
    assert live.read_bytes() == b"drain3-bytes"
