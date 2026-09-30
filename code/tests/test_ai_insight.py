"""Phase 98 — AI Insight Workflow + report soft-fail."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.api.report_files import (
    incident_id_from_report_filename,
    is_ai_insight_filename,
    is_safe_report_filename,
    list_report_files,
)
from src.copilot.insight_flow import (
    INSIGHT_DISCLAIMER,
    InsightFlowError,
    insight_filename,
    run_insight_workflow,
)
from src.copilot.provider import CopilotProviderError
from src.db.connection import get_connection
from src.reporting.persist import run_report
from src.reporting.report_generator import NothingToReport


def _config(tmp_path: Path, *, ai_insight: bool = False) -> dict:
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
            "html_template_path": "src/reporting/templates/incident_report.html.j2",
            "use_llm_narrative": False,
            "llm_model": "qwen3-coder:30b",
        },
        "orchestration": {"parallel_backend": "threads", "n_workers": 2},
        "copilot": {
            "enabled": False,
            "max_attachment_chars": 4000,
            "max_timeline_events": 20,
            "ai_insight": {"enabled": ai_insight},
        },
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


def test_insight_filename_and_safety() -> None:
    name = insight_filename("inc-1")
    assert name == "incident_inc-1_ai_insight.md"
    assert is_safe_report_filename(name)
    assert is_ai_insight_filename(name)
    assert incident_id_from_report_filename(name) == "inc-1"
    assert incident_id_from_report_filename("incident_inc-1.md") == "inc-1"
    assert not is_ai_insight_filename("incident_inc-1.md")


def test_run_insight_workflow_writes_disclaimer(tmp_path: Path) -> None:
    provider = MagicMock()
    provider.generate.return_value = "Plain-language summary of the incident."
    context = {
        "incident": {
            "incident_id": "inc-1",
            "severity": "medium",
            "entity_id": "alice",
            "start_time": "2024-01-01T12:00:00+00:00",
            "end_time": "2024-01-01T13:00:00+00:00",
            "summary_text": "stub",
        },
        "entity": {"entity_id": "alice", "entity_type": "user"},
        "anomalies": [
            {
                "source_detector": "statistical",
                "score": 5.0,
                "window_start": "2024-01-01T12:00:00+00:00",
                "window_end": "2024-01-01T13:00:00+00:00",
                "metadata": {},
            }
        ],
        "timeline": [],
    }
    path = run_insight_workflow(
        context=context,
        report_dir=tmp_path,
        provider=provider,
    )
    assert path.name == "incident_inc-1_ai_insight.md"
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# AI Insight")
    assert INSIGHT_DISCLAIMER in text
    assert "Plain-language summary of the incident." in text
    provider.generate.assert_called_once()


def test_run_insight_workflow_provider_error() -> None:
    provider = MagicMock()
    provider.generate.side_effect = CopilotProviderError("LLM unreachable")
    with pytest.raises(InsightFlowError, match="LLM unreachable"):
        run_insight_workflow(
            context={
                "incident": {"incident_id": "inc-1", "severity": "low"},
                "entity": {},
                "anomalies": [],
                "timeline": [],
            },
            report_dir=Path("."),
            provider=provider,
        )


def test_run_report_ai_insight_success(tmp_path: Path) -> None:
    config = _config(tmp_path, ai_insight=True)
    connection = get_connection(config)
    try:
        _seed_full(connection)
    finally:
        connection.close()

    fake = MagicMock()
    fake.generate.return_value = "Mentor-friendly insight prose."

    with (
        patch("src.reporting.persist.load_copilot_env_settings") as load_env,
        patch("src.reporting.persist.build_provider", return_value=fake),
    ):
        load_env.return_value = MagicMock()
        summary = run_report(config)

    assert summary.ai_insight_enabled is True
    assert summary.ai_insight_attempted == 1
    assert summary.ai_insight_successes == 1
    assert summary.ai_insight_skipped == 0
    assert summary.reports_written == 1

    report_dir = Path(config["paths"]["report_dir"])
    insight = report_dir / "incident_inc-1_ai_insight.md"
    assert insight.is_file()
    body = insight.read_text(encoding="utf-8")
    assert "# AI Insight" in body
    assert "Mentor-friendly insight prose." in body
    assert (report_dir / "incident_inc-1.md").is_file()

    items, total = list_report_files(report_dir)
    names = {item.filename for item in items}
    assert "incident_inc-1_ai_insight.md" in names
    insight_item = next(i for i in items if i.filename.endswith("_ai_insight.md"))
    assert insight_item.incident_id == "inc-1"
    assert total >= 3

    connection = get_connection(config)
    try:
        row = connection.execute(
            """
            SELECT params_json FROM pipeline_runs
            WHERE stage = 'report'
            ORDER BY started_at DESC LIMIT 1
            """
        ).fetchone()[0]
        import json

        params = json.loads(row) if isinstance(row, str) else row
        assert params["ai_insight_enabled"] is True
        assert params["summary"]["ai_insight_successes"] == 1
    finally:
        connection.close()


def test_run_report_ai_insight_soft_fail(tmp_path: Path) -> None:
    config = _config(tmp_path, ai_insight=True)
    connection = get_connection(config)
    try:
        _seed_full(connection)
    finally:
        connection.close()

    with (
        patch("src.reporting.persist.load_copilot_env_settings") as load_env,
        patch(
            "src.reporting.persist.build_provider",
            side_effect=CopilotProviderError("OLLAMA down"),
        ),
    ):
        load_env.return_value = MagicMock()
        summary = run_report(config)

    assert summary.reports_written == 1
    assert summary.ai_insight_attempted == 1
    assert summary.ai_insight_successes == 0
    assert summary.ai_insight_skipped == 1
    report_dir = Path(config["paths"]["report_dir"])
    assert (report_dir / "incident_inc-1.md").is_file()
    assert (report_dir / "incident_inc-1.html").is_file()
    assert not (report_dir / "incident_inc-1_ai_insight.md").exists()


def test_run_report_ai_insight_disabled_by_default(tmp_path: Path) -> None:
    config = _config(tmp_path, ai_insight=False)
    connection = get_connection(config)
    try:
        _seed_full(connection)
    finally:
        connection.close()

    with patch("src.reporting.persist.build_provider") as mocked:
        summary = run_report(config)
        mocked.assert_not_called()

    assert summary.ai_insight_enabled is False
    assert summary.ai_insight_attempted == 0
    assert not (
        Path(config["paths"]["report_dir"]) / "incident_inc-1_ai_insight.md"
    ).exists()


def test_run_report_nothing_to_report_still_records_insight_flag(tmp_path: Path) -> None:
    config = _config(tmp_path, ai_insight=True)
    with pytest.raises(NothingToReport):
        run_report(config)
