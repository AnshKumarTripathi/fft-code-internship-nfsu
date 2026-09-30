"""Regression: dashboard polls must not poison in-process pipeline writers."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from src.db.connection import get_connection, get_read_only_connection


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    return {
        "paths": {
            "raw_log_dir": str(data_root / "raw"),
            "parsed_dir": str(data_root / "parsed"),
            "timeseries_dir": str(data_root / "timeseries"),
            "baseline_dir": str(data_root / "baselines"),
            "scores_dir": str(data_root / "scores"),
            "report_dir": str(data_root / "reports"),
            "db_path": str(data_root / "warehouse.duckdb"),
        }
    }


def test_reader_and_writer_coexist_same_process(tmp_path: Path) -> None:
    """UI read handle + pipeline writer must share DuckDB access mode."""
    config = _temp_config(tmp_path)
    writer = get_connection(config)
    try:
        reader = get_read_only_connection(config)
        try:
            assert reader.execute("SELECT 1").fetchone()[0] == 1
            writer.execute(
                "INSERT INTO entities (entity_id, entity_type) VALUES ('e1', 'user')"
            )
            assert (
                reader.execute(
                    "SELECT COUNT(*) FROM entities WHERE entity_id = 'e1'"
                ).fetchone()[0]
                == 1
            )
        finally:
            reader.close()
    finally:
        writer.close()


def test_writer_survives_concurrent_dashboard_polls(tmp_path: Path) -> None:
    """Regression for ingest 'different configuration' while analyses poll."""
    config = _temp_config(tmp_path)
    bootstrap = get_connection(config)
    bootstrap.close()

    stop = threading.Event()
    errors: list[BaseException] = []
    polls = {"n": 0}

    def poll_reader() -> None:
        while not stop.is_set():
            try:
                conn = get_read_only_connection(config)
                try:
                    conn.execute("SELECT 1").fetchone()
                    polls["n"] += 1
                finally:
                    conn.close()
            except BaseException as exc:  # noqa: BLE001 — collect then assert
                errors.append(exc)
                return
            time.sleep(0.01)

    poller = threading.Thread(target=poll_reader)
    poller.start()
    time.sleep(0.05)
    try:
        for _ in range(5):
            conn = get_connection(config)
            try:
                conn.execute("SELECT COUNT(*) FROM entities").fetchone()
            finally:
                conn.close()
            time.sleep(0.02)
    finally:
        stop.set()
        poller.join(timeout=5.0)

    assert errors == [], f"poll errors: {errors}"
    assert polls["n"] >= 3
    assert not poller.is_alive()
