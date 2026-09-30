"""End-to-end report pipeline tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from src.db.connection import get_connection
from src.reporting.narrative_llm import NarrativeLlmError
from src.reporting.persist import run_report
from src.reporting.report_generator import NothingToReport


def _config(tmp_path: Path, *, use_llm: bool = False) -> dict:
    data = tmp_path / "data"
    return {
        "paths": {
            "raw_log_dir": str(data / "raw"),
            "parsed_dir": str(data / "parsed"),
            "timeseries_dir": str(data / "timeseries"),
            "baseline_dir": str(data / "baselines"),
            "scores_dir": str(data / "scores"),
            "report_dir": str(data / "reports"),
            "db_path": str(data / "warehouse.duckdb"),
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
            "use_llm_narrative": use_llm,
            "llm_model": "qwen3-coder:30b",
        },
        "orchestration": {"parallel_backend": "dask", "n_workers": 8},
    }


def _seed_full(connection) -> None:
    start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
    connection.execute(
        """
        INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
        VALUES ('alice', 'user', ?, ?)
        ON CONFLICT (entity_id) DO NOTHING
        """,
        [start, end],
    )
    connection.execute(
        """
        INSERT INTO templates
        (template_id, template_string, first_seen, last_seen, occurrence_count)
        VALUES ('t1', 'Accepted password for <*>', ?, ?, 1)
        ON CONFLICT (template_id) DO NOTHING
        """,
        [start, end],
    )
    connection.execute(
        """
        INSERT INTO parsed_events
        (event_id, entity_id, template_id, event_timestamp, log_source, raw_fields, ingested_at)
        VALUES (1, 'alice', 't1', ?, 'ssh', '{"src_ip": "10.0.0.1"}'::JSON, ?)
        """,
        [start, start],
    )
    connection.execute(
        """
        INSERT INTO anomaly_events
        (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
        VALUES ('anom-1', 'alice', ?, ?, 'statistical', 5.0, '{"rate_z": 5.0}'::JSON)
        """,
        [start, end],
    )
    connection.execute(
        """
        INSERT INTO correlation_edges
        (edge_id, src_event_id, dst_anomaly_id, relation_type, session_id)
        VALUES ('edge-1', 1, 'anom-1', 'precedes', 'sess-1')
        """
    )
    connection.execute(
        """
        INSERT INTO incidents
        (incident_id, entity_id, start_time, end_time, severity, summary_text, contributing_anomaly_ids)
        VALUES ('inc-1', 'alice', ?, ?, 'medium', 'stub summary', ?)
        """,
        [start, end, ["anom-1"]],
    )


def test_run_report_nothing_to_report(tmp_path: Path) -> None:
    config = _config(tmp_path)
    with pytest.raises(NothingToReport, match="nothing to report"):
        run_report(config)


def test_run_report_writes_markdown_and_html(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        _seed_full(connection)
    finally:
        connection.close()

    with patch("src.reporting.persist.summarize_incident") as mocked:
        summary = run_report(config)
        mocked.assert_not_called()
    assert summary.reports_written == 1
    assert summary.llm_enabled is False
    report_dir = Path(config["paths"]["report_dir"])
    md_files = list(report_dir.glob("incident_*.md"))
    html_files = list(report_dir.glob("incident_*.html"))
    assert len(md_files) == 1
    assert len(html_files) == 1
    text = md_files[0].read_text(encoding="utf-8")
    html = html_files[0].read_text(encoding="utf-8")
    assert "inc-1" in text
    assert "medium" in text
    assert "precedes" in text
    assert "<!DOCTYPE html>" in html
    assert "precedes" in html
    assert "LLM narrative" not in text
    assert "LLM narrative" not in html

    connection = get_connection(config)
    try:
        status = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'report'
            ORDER BY started_at DESC LIMIT 1
            """
        ).fetchone()[0]
        assert status == "success"
    finally:
        connection.close()


def test_run_report_overwrites_on_rerun(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        _seed_full(connection)
    finally:
        connection.close()
    first = run_report(config)
    report_dir = Path(config["paths"]["report_dir"])
    md_path = report_dir / "incident_inc-1.md"
    html_path = report_dir / "incident_inc-1.html"
    md_path.write_text("stale markdown", encoding="utf-8")
    html_path.write_text("stale html", encoding="utf-8")
    second = run_report(config)
    assert second.reports_written == 1
    assert len(list(report_dir.glob("incident_*"))) == 2
    assert "stale markdown" not in md_path.read_text(encoding="utf-8")
    assert "stale html" not in html_path.read_text(encoding="utf-8")
    assert "inc-1" in md_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_path.read_text(encoding="utf-8")
    assert first.report_paths == second.report_paths


def test_run_report_llm_failure_still_writes(tmp_path: Path) -> None:
    config = _config(tmp_path, use_llm=True)
    connection = get_connection(config)
    try:
        _seed_full(connection)
    finally:
        connection.close()

    with patch(
        "src.reporting.persist.summarize_incident",
        side_effect=NarrativeLlmError("ollama down"),
    ):
        summary = run_report(config)

    assert summary.reports_written == 1
    assert summary.llm_failures == 1
    assert summary.llm_successes == 0
    md = Path(summary.report_paths[0]).read_text(encoding="utf-8")
    html = Path(summary.report_paths[1]).read_text(encoding="utf-8")
    assert "LLM narrative" not in md
    assert "LLM narrative" not in html
    assert "inc-1" in md
    assert "<!DOCTYPE html>" in html


def test_run_report_llm_success_prepends_and_updates_summary(tmp_path: Path) -> None:
    config = _config(tmp_path, use_llm=True)
    connection = get_connection(config)
    try:
        _seed_full(connection)
    finally:
        connection.close()

    with patch(
        "src.reporting.persist.summarize_incident",
        return_value="Prose from local model.",
    ):
        summary = run_report(config)

    assert summary.llm_successes == 1
    md = Path(summary.report_paths[0]).read_text(encoding="utf-8")
    html = Path(summary.report_paths[1]).read_text(encoding="utf-8")
    assert md.startswith("# Incident Report")
    assert "LLM narrative" in md
    assert "Prose from local model." in md
    assert "LLM narrative" in html
    assert "Prose from local model." in html

    connection = get_connection(config)
    try:
        summary_text = connection.execute(
            "SELECT summary_text FROM incidents WHERE incident_id = 'inc-1'"
        ).fetchone()[0]
        assert summary_text == "Prose from local model."
    finally:
        connection.close()
