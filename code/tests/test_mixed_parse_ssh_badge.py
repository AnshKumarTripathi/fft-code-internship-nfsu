"""Mixed SSH + badge ingest/parse (Phase 33)."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse

SSH_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "ssh_extended.log"
BADGE_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "physical" / "badge.csv"
)
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(BADGE_FIXTURE, raw / "badge.csv")
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


def test_mixed_parse_ssh_and_badge(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert "ssh" in sources
        assert "badge" in sources
    finally:
        connection.close()
