"""R6: corrupt parquet isolation, ingest dead-letter, STFT cap, writer lock."""

from __future__ import annotations

import multiprocessing
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.db.connection import get_connection
from src.db.writer_lock import WarehouseBusyError, WriterLock
from src.detectors.spectral.persist import SpectralEntityWork, compute_entity_spectral
from src.ingestion.persist import ingest_dead_letter_dir, ingest_staging_dir, run_ingest
from src.parsing.persist import ParseError, run_parse

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"
UTC = timezone.utc


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(FIXTURE, raw / "auth.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
    return {
        "paths": {
            "raw_log_dir": str(raw),
            "parsed_dir": str(data_root / "parsed"),
            "timeseries_dir": str(data_root / "timeseries"),
            "baseline_dir": str(data_root / "baselines"),
            "scores_dir": str(data_root / "scores"),
            "report_dir": str(data_root / "reports"),
            "db_path": str(data_root / "warehouse.duckdb"),
        },
        "bucketing": {"bucket_seconds": 600},
        "statistical": {"window_buckets": 6, "z_threshold": 4.0},
        "spectral": {
            "window_hours": 72,
            "step_fraction": 0.333,
            "baseline_max_nperseg": 1440,
            "z_threshold": 4.0,
            "cluster_eps": 1.2,
            "cluster_min_samples": 2,
            "max_buckets_per_entity": 100000,
        },
        "ml": {
            "model_type": "isolation_forest",
            "onnx_model_path": None,
            "contamination": 0.02,
        },
        "correlation": {
            "session_gap_minutes": 30,
            "same_ip_link": True,
            "same_host_link": True,
        },
        "reporting": {
            "template_path": "src/reporting/templates/incident_report.md.j2",
            "use_llm_narrative": False,
            "llm_model": "qwen3-coder:30b",
        },
        "orchestration": {
            "parallel_backend": "dask",
            "n_workers": 8,
            "run_all_require_complete": False,
        },
        "_config_path": str(config_dir / "pipeline.yaml"),
    }


def test_corrupt_staging_parquet_is_skipped_and_recorded(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    staging = ingest_staging_dir(config)
    junk = staging / "part-99999.parquet"
    junk.write_bytes(b"this is not parquet")

    summary = run_parse(config, config_path=config_path)
    assert summary.events_written > 0

    connection = get_connection(config)
    try:
        errors = connection.execute(
            "SELECT source_path, stage FROM pipeline_errors WHERE stage = 'parse'"
        ).fetchall()
        assert errors
        assert any("part-99999.parquet" in str(row[0]) for row in errors)
    finally:
        connection.close()

    config["orchestration"]["run_all_require_complete"] = True
    with pytest.raises(ParseError, match="corrupt parquet"):
        run_parse(config, config_path=config_path)


def test_oversized_line_goes_to_dead_letter(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    config["ingestion"] = {"max_line_bytes": 1000}
    raw = Path(config["paths"]["raw_log_dir"])
    (raw / "huge.log").write_text("x" * 5000 + "\n", encoding="utf-8")

    summary = run_ingest(config, config_path=config_path)
    assert summary.lines_dead_lettered >= 1
    dead = ingest_dead_letter_dir(config) / "dead-letter.jsonl"
    assert dead.is_file()
    text = dead.read_text(encoding="utf-8")
    assert "line_too_long" in text
    assert summary.lines_kept > 0


def test_stft_cap_skips_huge_entity_without_scoring() -> None:
    n = 20
    starts = tuple(
        datetime(2024, 1, 1, tzinfo=UTC) for _ in range(n)
    )
    work = SpectralEntityWork(
        entity_id="huge",
        bucket_starts=starts,
        event_counts=tuple(1.0 for _ in range(n)),
        bucket_seconds=600,
        window_buckets=6,
        step_buckets=2,
        z_threshold=4.0,
        baseline_max_nperseg=1440,
        fft_window="hann",
        min_welch_length=4,
        max_buckets_per_entity=5,
    )
    result = compute_entity_spectral(work)
    assert result.skip_reason == "cap_exceeded"
    assert result.baseline is None
    assert result.window_rows == ()


def _hold_writer_lock(lock_path: str, ready_name: str, hold_name: str) -> None:
    lock = WriterLock(lock_path)
    lock.acquire()
    Path(ready_name).write_text("ready", encoding="utf-8")
    deadline = time.time() + 30
    while time.time() < deadline:
        if Path(hold_name).exists():
            break
        time.sleep(0.05)
    lock.release()


def test_second_process_cannot_take_writer_lock(tmp_path: Path) -> None:
    lock_path = str(tmp_path / "warehouse.duckdb.writer.lock")
    ready = tmp_path / "ready.txt"
    hold = tmp_path / "hold.txt"
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(
        target=_hold_writer_lock,
        args=(lock_path, str(ready), str(hold)),
    )
    proc.start()
    try:
        deadline = time.time() + 30
        while time.time() < deadline and not ready.exists():
            time.sleep(0.05)
        assert ready.exists(), "child did not acquire lock"
        with pytest.raises(WarehouseBusyError, match="locked by another writer"):
            WriterLock(lock_path).acquire()
        hold.write_text("done", encoding="utf-8")
        proc.join(timeout=30)
        assert proc.exitcode == 0
        lock = WriterLock(lock_path)
        lock.acquire()
        lock.release()
    finally:
        if not hold.exists():
            hold.write_text("done", encoding="utf-8")
        proc.join(timeout=5)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)


def test_load_test_procedure_is_written() -> None:
    root = Path(__file__).resolve().parents[1]
    readme = root / "tests" / "load" / "README.md"
    script = root / "scripts" / "load_test_spectral.py"
    assert readme.is_file()
    text = readme.read_text(encoding="utf-8")
    assert "scale 10" in text
    assert "max_buckets_per_entity" in text
    assert script.is_file()
    help_result = subprocess.run(
        [sys.executable, str(script), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "baseline-buckets" in help_result.stdout
