"""Mixed v3 freeze corpus: parse, bucket, run-all smoke, SSH allowlist (Phase 36)."""

from __future__ import annotations

import shutil
from pathlib import Path

from src import pipeline
from src.db.connection import get_connection
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse
from src.timeseries.persist import run_bucket

MIXED_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "mixed_v3"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"

_MIXED_FILES = ("ssh_extended.log", "security.txt", "pfsense.txt")
_EXPECTED_SOURCES = frozenset({"ssh", "windows_security", "firewall"})


def _copy_mixed(raw: Path) -> None:
    raw.mkdir(parents=True, exist_ok=True)
    for name in _MIXED_FILES:
        shutil.copy(MIXED_DIR / name, raw / name)


def _temp_config(
    tmp_path: Path,
    *,
    enabled_sources: list[str] | None = None,
) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    _copy_mixed(raw)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
    config: dict = {
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
    if enabled_sources is not None:
        config["ingestion"] = {"enabled_sources": enabled_sources}
    return config


def _parsed_sources(config: dict) -> set[str]:
    connection = get_connection(config)
    try:
        return {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
    finally:
        connection.close()


def _summary_line(captured: str, label: str) -> str:
    prefix = f"  {label}:"
    for line in captured.splitlines():
        if line.startswith(prefix):
            return line
    return ""


def test_mixed_v3_parse_has_three_families(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    sources = _parsed_sources(config)
    assert len(sources) >= 3
    assert _EXPECTED_SOURCES <= sources


def test_mixed_v3_bucket_smoke(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    summary = run_bucket(config, config_path=config_path)

    assert summary.total_buckets_written > 0
    connection = get_connection(config)
    try:
        bucket_row_count = connection.execute(
            "SELECT COUNT(*) FROM entity_bucket_counts"
        ).fetchone()[0]
        assert bucket_row_count > 0
    finally:
        connection.close()


def test_mixed_v3_run_all_exits_zero(tmp_path: Path, capsys) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    rc = pipeline.run_all(config, config_path=config_path, require_complete=False)
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert rc == 0, combined
    ran = _summary_line(combined, "ran")
    failed = _summary_line(combined, "failed")
    assert "ingest" in ran
    assert "parse" in ran
    assert "bucket" in ran
    assert "(none)" in failed
    sources = _parsed_sources(config)
    assert _EXPECTED_SOURCES <= sources


def test_mixed_v3_ssh_allowlist(tmp_path: Path) -> None:
    config = _temp_config(tmp_path, enabled_sources=["ssh"])
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    sources = _parsed_sources(config)
    assert sources == {"ssh"}
