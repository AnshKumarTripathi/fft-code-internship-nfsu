"""End-to-end parse pipeline tests (ingest fixture → parse)."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.persist import run_ingest
from src.parsing.persist import ParseError, run_parse
from src.parsing.writers import events_output_dir

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"
EXTENDED_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "ssh_extended.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"


def _temp_config(tmp_path: Path, fixture: Path = FIXTURE) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(fixture, raw / "auth.log")
    # Copy drain3.ini next to a temp pipeline.yaml for resolve_drain3_ini
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


def test_parse_requires_staging(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    # No ingest yet
    import pytest

    with pytest.raises(ParseError, match="run ingest first"):
        run_parse(config, config_path=config["_config_path"])


def test_run_parse_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    raw_dir = Path(config["paths"]["raw_log_dir"])
    (raw_dir / "noise.log").write_text("not a structured log line\n", encoding="utf-8")

    run_ingest(config, config_path=config_path)
    summary = run_parse(config, config_path=config_path)

    assert summary.staging_rows_read > 0
    assert summary.events_written > 0
    assert summary.templates_total > 0
    assert summary.rows_skipped_missing_entity_or_ts >= 1

    events_dir = events_output_dir(config)
    partitions = list(events_dir.glob("event_date=*"))
    assert partitions
    assert any(events_dir.glob("event_date=*/*.parquet"))

    connection = get_connection(config)
    try:
        template_count = connection.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
        assert template_count == summary.templates_total
        assert template_count > 0

        event_count = connection.execute("SELECT COUNT(*) FROM parsed_events").fetchone()[0]
        assert event_count == summary.events_written
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert "ssh" in sources
        assert "linux_kern" in sources
        assert "linux_cron" in sources

        freq = connection.execute(
            "SELECT template_id, count(*) AS c FROM parsed_events "
            "GROUP BY template_id ORDER BY c DESC"
        ).fetchall()
        assert len(freq) >= 1

        runs = connection.execute(
            "SELECT status FROM pipeline_runs WHERE stage = 'parse' ORDER BY started_at DESC"
        ).fetchone()
        assert runs[0] == "success"
    finally:
        connection.close()


def test_reparse_clears_stale_correlation_edges(tmp_path: Path) -> None:
    """Parse must drop correlation_edges before DELETE FROM parsed_events (FK)."""
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        event_id = connection.execute(
            "SELECT event_id FROM parsed_events ORDER BY event_id LIMIT 1"
        ).fetchone()[0]
        entity_id = connection.execute(
            "SELECT entity_id FROM parsed_events WHERE event_id = ?",
            [event_id],
        ).fetchone()[0]
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        connection.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
            VALUES ('anom-stale', ?, ?, ?, 'ml', 1.0, '{}'::JSON)
            """,
            [entity_id, start, start],
        )
        connection.execute(
            """
            INSERT INTO correlation_edges
            (edge_id, src_event_id, dst_anomaly_id, relation_type, session_id)
            VALUES ('edge-stale', ?, 'anom-stale', 'precedes', 'sess-stale')
            """,
            [event_id],
        )
    finally:
        connection.close()

    second = run_parse(config, config_path=config_path)
    assert second.events_written > 0

    connection = get_connection(config)
    try:
        edges = connection.execute("SELECT COUNT(*) FROM correlation_edges").fetchone()[0]
        anomalies = connection.execute("SELECT COUNT(*) FROM anomaly_events").fetchone()[0]
        assert edges == 0
        assert anomalies == 0
        events = connection.execute("SELECT COUNT(*) FROM parsed_events").fetchone()[0]
        assert events == second.events_written
    finally:
        connection.close()


def test_reparse_does_not_explode_template_cardinality(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    run_ingest(config, config_path=config_path)
    first = run_parse(config, config_path=config_path)
    second = run_parse(config, config_path=config_path)

    assert second.events_written == first.events_written
    # Same corpus + Drain3 state: template count should stay bounded / stable
    assert second.templates_total <= first.templates_total + 2
    assert second.templates_total >= 1


def test_parse_session_and_disconnect_lines(tmp_path: Path) -> None:
    config = _temp_config(tmp_path, EXTENDED_FIXTURE)
    config_path = config.pop("_config_path")

    ingest = run_ingest(config, config_path=config_path)
    assert ingest.extraction_failures == 0
    summary = run_parse(config, config_path=config_path)
    assert summary.rows_skipped_missing_entity_or_ts == 0
    assert summary.events_written >= 8

    connection = get_connection(config)
    try:
        results = connection.execute(
            """
            SELECT entity_id, raw_fields
            FROM parsed_events
            """
        ).fetchall()
        auth_results = []
        hostnames = set()
        for entity_id, raw_fields in results:
            payload = raw_fields
            if isinstance(payload, str):
                payload = json.loads(payload)
            auth_results.append(payload.get("auth_result"))
            if payload.get("hostname"):
                hostnames.add(payload["hostname"])
        assert "session_opened" in auth_results
        assert "session_closed" in auth_results
        assert "disconnect" in auth_results
        assert "no_ident" in auth_results
        assert "breakin" in auth_results
        assert "hostname" in hostnames
        assert any(row[0] == "alice" for row in results)
    finally:
        connection.close()

