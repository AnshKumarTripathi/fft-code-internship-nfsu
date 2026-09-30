"""End-to-end detect-statistical pipeline tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from src.db.connection import get_connection
from src.detectors.statistical.persist import StatisticalError, run_detect_statistical
from src.detectors.statistical.writers import statistical_scores_dir
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse
from src.timeseries.persist import run_bucket

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"


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
        "orchestration": {"parallel_backend": "dask", "n_workers": 8},
        "_config_path": str(config_dir / "pipeline.yaml"),
    }


def test_detect_statistical_requires_buckets(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    with pytest.raises(StatisticalError, match="run bucket first"):
        run_detect_statistical(config, config_path=config_path)


def test_run_detect_statistical_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    run_bucket(config, config_path=config_path)
    summary = run_detect_statistical(config, config_path=config_path)

    assert summary.windows_total >= 0
    assert summary.max_rate_z >= 0.0

    scores_dir = statistical_scores_dir(config)
    if summary.entities_scored > 0:
        assert list(scores_dir.glob("entity_id=*/*.parquet"))

    connection = get_connection(config)
    try:
        score_count = connection.execute(
            "SELECT COUNT(*) FROM statistical_window_scores"
        ).fetchone()[0]
        assert score_count == summary.windows_total

        run_row = connection.execute(
            """
            SELECT status, params_json FROM pipeline_runs
            WHERE stage = 'detect-statistical'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
        assert run_row[0] == "success"
        params = run_row[1]
        if isinstance(params, str):
            import json

            params = json.loads(params)
        summary_params = params.get("summary", params)
        assert "n_workers_used" in summary_params or "n_workers_used" in params
        assert summary.n_workers_used >= 1
        assert summary.parallel_backend
    finally:
        connection.close()
