"""Unit tests for deterministic report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.db.connection import get_connection
from src.reporting.report_generator import (
    IncidentRow,
    build_context,
    render_incident_html,
    render_incident_markdown,
    report_filename,
    write_incident_report,
)


def _config(tmp_path: Path) -> dict:
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
            "use_llm_narrative": False,
            "llm_model": "qwen3-coder:30b",
        },
        "orchestration": {"parallel_backend": "dask", "n_workers": 8},
    }


def _seed_incident(connection) -> IncidentRow:
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
        INSERT INTO anomaly_events
        (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
        VALUES ('anom-1', 'alice', ?, ?, 'statistical', 5.0, '{"rate_z": 5.0}'::JSON)
        """,
        [start, end],
    )
    connection.execute(
        """
        INSERT INTO incidents
        (incident_id, entity_id, start_time, end_time, severity, summary_text, contributing_anomaly_ids)
        VALUES ('inc-1', 'alice', ?, ?, 'medium', '1 anomaly across 1 detector (statistical)', ?)
        """,
        [start, end, ["anom-1"]],
    )
    return IncidentRow(
        incident_id="inc-1",
        entity_id="alice",
        start_time=start,
        end_time=end,
        severity="medium",
        summary_text="1 anomaly across 1 detector (statistical)",
        contributing_anomaly_ids=["anom-1"],
    )


def test_render_contains_incident_id_and_severity(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        incident = _seed_incident(connection)
        context = build_context(connection, incident)
        markdown = render_incident_markdown(
            context,
            template_path=config["reporting"]["template_path"],
        )
    finally:
        connection.close()

    assert markdown.strip()
    assert "inc-1" in markdown
    assert "medium" in markdown
    assert "statistical" in markdown
    assert "deterministic report" in markdown
    assert "## Why flagged" in markdown
    assert "Investigate a rate burst" in markdown
    assert "## Detector agreement" in markdown
    assert "## Correlation edges (counts)" in markdown
    assert "## Notes" in markdown
    assert "## Analyst actions" in markdown
    assert "No analyst actions recorded" in markdown
    assert "high event *rates* only" in markdown
    assert "KNOWN_LIMITATIONS.md" in markdown
    assert "Showing 1 of 1 anomalies" in markdown
    assert "## Activity" in markdown
    assert "## Spectral fingerprint" in markdown
    assert "## Top anomalies by detector" in markdown


def test_render_html_contains_precedes(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        incident = _seed_incident(connection)
        start = incident.start_time
        connection.execute(
            """
            INSERT INTO templates
            (template_id, template_string, first_seen, last_seen, occurrence_count)
            VALUES ('t1', 'Failed password for <*>', ?, ?, 1)
            """,
            [start, start],
        )
        connection.execute(
            """
            INSERT INTO parsed_events
            (event_id, entity_id, template_id, event_timestamp, log_source, raw_fields, ingested_at)
            VALUES (1, 'alice', 't1', ?, 'ssh', '{}'::JSON, ?)
            """,
            [start, start],
        )
        connection.execute(
            """
            INSERT INTO correlation_edges
            (edge_id, src_event_id, dst_anomaly_id, relation_type, session_id)
            VALUES ('edge-1', 1, 'anom-1', 'precedes', 'sess-1')
            """
        )
        context = build_context(connection, incident)
        html = render_incident_html(
            context,
            template_path="src/reporting/templates/incident_report.html.j2",
        )
    finally:
        connection.close()

    assert html.strip()
    assert "<!DOCTYPE html>" in html
    assert "precedes" in html
    assert "inc-1" in html
    assert "chart.js" not in html.lower()
    assert "cdn." not in html.lower()
    assert "ssh" in html
    assert "Showing 1 of 1 anomalies" in html
    assert "KNOWN_LIMITATIONS.md" in html
    assert "Why flagged" in html
    assert "Investigate a rate burst" in html


def test_report_caps_anomalies_and_embeds_svg(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [start, end],
        )
        ids: list[str] = []
        for index in range(25):
            anomaly_id = f"anom-{index:02d}"
            ids.append(anomaly_id)
            bucket = start.replace(minute=index)
            connection.execute(
                """
                INSERT INTO anomaly_events
                (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
                VALUES (?, 'alice', ?, ?, 'statistical', ?, '{"rate_z": 1}'::JSON)
                """,
                [anomaly_id, bucket, end, float(index + 1)],
            )
            connection.execute(
                """
                INSERT INTO entity_bucket_counts
                (entity_id, bucket_start, bucket_seconds, event_count)
                VALUES ('alice', ?, 600, ?)
                """,
                [bucket, float(index + 3)],
            )
        connection.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity, summary_text, contributing_anomaly_ids)
            VALUES ('inc-cap', 'alice', ?, ?, 'high', 'many anomalies', ?)
            """,
            [start, end, ids],
        )
        freq = [0.0, 0.1, 0.2, 0.3]
        psd = [1.0, 0.8, 0.4, 0.1]
        connection.execute(
            """
            INSERT INTO spectral_baselines
            (entity_id, computed_at, bucket_seconds, nperseg, freq_grid, psd, psd_norm)
            VALUES ('alice', ?, 600, 16, ?, ?, ?)
            """,
            [start, freq, freq, psd],
        )
        connection.execute(
            """
            INSERT INTO entity_spectral_features
            (entity_id, dominant_period_hours, dominant_power_frac, spectral_entropy, total_power, computed_at)
            VALUES ('alice', 24.0, 0.5, 1.2, 3.0, ?)
            """,
            [start],
        )
        incident = IncidentRow(
            incident_id="inc-cap",
            entity_id="alice",
            start_time=start,
            end_time=end,
            severity="high",
            summary_text="many anomalies",
            contributing_anomaly_ids=ids,
        )
        context = build_context(connection, incident)
        markdown = render_incident_markdown(
            context,
            template_path=config["reporting"]["template_path"],
        )
        html = render_incident_html(
            context,
            template_path="src/reporting/templates/incident_report.html.j2",
        )
    finally:
        connection.close()

    assert context["anomalies_total"] == 25
    assert context["anomalies_shown"] == 20
    assert "Showing 20 of 25 anomalies" in markdown
    assert "Showing 20 of 25 anomalies" in html
    assert "<svg" in html
    assert "cdn." not in html.lower()


def test_overwrite_replaces_file_content(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    path = write_incident_report(report_dir, "inc-1", "first version")
    assert path.read_text(encoding="utf-8") == "first version"
    write_incident_report(report_dir, "inc-1", "second version")
    assert path.read_text(encoding="utf-8") == "second version"
    assert report_filename("inc-1") == "incident_inc-1.md"
    html_path = write_incident_report(
        report_dir, "inc-1", "<html>second</html>", suffix="html"
    )
    assert html_path.name == "incident_inc-1.html"
    assert html_path.read_text(encoding="utf-8") == "<html>second</html>"
    assert report_filename("inc-1", suffix="html") == "incident_inc-1.html"
