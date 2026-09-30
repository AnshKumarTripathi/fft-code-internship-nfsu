"""Phase 10 FastAPI dashboard tests (requires requirements-api.txt)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from src.db.connection import get_connection, get_read_only_connection

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402


def _full_config(tmp_path: Path) -> dict:
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
        "dashboard": {"serve_legacy_html": True},
    }


def _write_config(tmp_path: Path, config: dict) -> Path:
    path = tmp_path / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def _seed_empty_warehouse(config: dict) -> None:
    conn = get_connection(config)
    conn.close()


def _seed_incident_warehouse(config: dict) -> None:
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES ('alice', 'user', ?, ?, 'Alice')
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO templates
            (template_id, template_string, first_seen, last_seen, occurrence_count)
            VALUES ('t1', 'Failed password for <*> from <*>', ?, ?, 3)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO parsed_events
            (event_id, entity_id, template_id, event_timestamp, log_source, raw_fields, ingested_at)
            VALUES (1, 'alice', 't1', ?, 'ssh', '{"src_ip": "10.0.0.9"}'::JSON, ?)
            """,
            [start, start],
        )
        conn.execute(
            """
            INSERT INTO entity_bucket_counts
            (entity_id, bucket_start, bucket_seconds, event_count)
            VALUES ('alice', ?, 600, 4.0)
            """,
            [start],
        )
        conn.execute(
            """
            INSERT INTO spectral_baselines
            (entity_id, computed_at, bucket_seconds, nperseg, freq_grid, psd, psd_norm)
            VALUES ('alice', ?, 600, 64, [0.0, 0.1, 0.2], [1.0, 2.0, 1.5], [0.1, 0.5, 0.4])
            """,
            [start],
        )
        conn.execute(
            """
            INSERT INTO entity_spectral_features
            (entity_id, dominant_period_hours, dominant_power_frac,
             spectral_entropy, total_power, computed_at)
            VALUES ('alice', 24.0, 0.42, 1.1, 3.5, ?)
            """,
            [start],
        )
        conn.execute(
            """
            INSERT INTO spectral_window_scores
            (entity_id, window_start, window_end, energy_z, shape_js_z, flagged)
            VALUES ('alice', ?, ?, 4.5, 1.2, TRUE)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
            VALUES ('anom-1', 'alice', ?, ?, 'statistical', 5.2, '{"rate_z": 5.2}'::JSON)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO correlation_edges
            (edge_id, src_event_id, dst_anomaly_id, relation_type, session_id)
            VALUES ('edge-1', 1, 'anom-1', 'precedes', 'sess-1')
            """
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES (
              'inc-1', 'alice', ?, ?, 'high',
              'Rate spike on alice (statistical)',
              ['anom-1']
            )
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO pipeline_runs
            (run_id, stage, started_at, finished_at, status, params_json)
            VALUES
              ('run-ingest', 'ingest', ?, ?, 'success', '{}'::JSON),
              ('run-parse', 'parse', ?, ?, 'success', '{}'::JSON)
            """,
            [start, end, start, end],
        )
    finally:
        conn.close()


@pytest.fixture
def empty_client(tmp_path: Path) -> TestClient:
    config = _full_config(tmp_path)
    _seed_empty_warehouse(config)
    config_path = _write_config(tmp_path, config)
    app = create_app(config_path)
    return TestClient(app)


@pytest.fixture
def seeded_client(tmp_path: Path) -> TestClient:
    config = _full_config(tmp_path)
    _seed_incident_warehouse(config)
    config_path = _write_config(tmp_path, config)
    app = create_app(config_path)
    return TestClient(app)


def test_api_incidents_empty(empty_client: TestClient) -> None:
    response = empty_client.get("/api/incidents")
    assert response.status_code == 200
    assert response.json() == []


def test_html_incidents_empty_copy(empty_client: TestClient) -> None:
    response = empty_client.get("/")
    assert response.status_code == 200
    assert "No incidents in warehouse" in response.text


def test_health_ok(seeded_client: TestClient) -> None:
    response = seeded_client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["db"] == "not_checked"

    ready = seeded_client.get("/health/ready")
    assert ready.status_code == 200
    ready_body = ready.json()
    assert ready_body["status"] == "ok"
    assert ready_body["db"] == "reachable"


def test_health_without_warehouse_file(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["db"] == "not_checked"
    ready = client.get("/health/ready")
    assert ready.status_code == 503


def test_api_and_html_runs(seeded_client: TestClient) -> None:
    api = seeded_client.get("/api/runs")
    assert api.status_code == 200
    stages = {item["stage"] for item in api.json()}
    assert "ingest" in stages
    assert "parse" in stages
    html = seeded_client.get("/runs")
    assert html.status_code == 200
    assert "pipeline_runs" in html.text or "Runs" in html.text
    assert "ingest" in html.text


def test_warehouse_lock_html_503(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import duckdb

    config = _full_config(tmp_path)
    _seed_empty_warehouse(config)
    config_path = _write_config(tmp_path, config)
    app = create_app(config_path)

    def raise_lock(_config: dict) -> None:
        error_cls = getattr(duckdb, "IOException", duckdb.Error)
        raise error_cls("Could not set lock on file: warehouse.duckdb")

    monkeypatch.setattr("src.api.deps.get_read_only_connection", raise_lock)
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 503
    assert "Warehouse is busy or missing" in response.text
    assert "text/html" in response.headers.get("content-type", "")

    api = client.get("/api/incidents")
    assert api.status_code == 503
    assert "detail" in api.json()



def test_api_incidents_seeded(seeded_client: TestClient) -> None:
    response = seeded_client.get("/api/incidents")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["incident_id"] == "inc-1"
    assert items[0]["entity_id"] == "alice"
    assert items[0]["severity"] == "high"


def test_html_incident_and_entity(seeded_client: TestClient) -> None:
    list_resp = seeded_client.get("/")
    assert list_resp.status_code == 200
    assert "inc-1" in list_resp.text
    assert "alice" in list_resp.text

    detail = seeded_client.get("/incidents/inc-1")
    assert detail.status_code == 200
    assert "Rate spike on alice" in detail.text
    assert "statistical" in detail.text

    entity = seeded_client.get("/entities/alice")
    assert entity.status_code == 200
    assert "Failed password for" in entity.text
    assert "activity-chart" in entity.text
    assert "psd-chart" in entity.text


def test_unknown_entity_404(seeded_client: TestClient) -> None:
    assert seeded_client.get("/api/entities/nobody/timeline").status_code == 404
    assert seeded_client.get("/api/entities/nobody/spectrum").status_code == 404
    assert seeded_client.get("/entities/nobody").status_code == 404


def test_timeline_and_spectrum(seeded_client: TestClient) -> None:
    timeline = seeded_client.get("/api/entities/alice/timeline")
    assert timeline.status_code == 200
    events = timeline.json()
    assert len(events) == 1
    assert events[0]["event_id"] == 1
    assert "anom-1" in events[0]["related_anomaly_ids"]

    spectrum = seeded_client.get("/api/entities/alice/spectrum")
    assert spectrum.status_code == 200
    body = spectrum.json()
    assert body["features"]["dominant_period_hours"] == 24.0
    assert body["freq_grid"] == [0.0, 0.1, 0.2]
    assert body["psd_norm"] == [0.1, 0.5, 0.4]
    assert body["bucket_seconds"] == 600


def test_dashboard_connection_allows_select_alongside_writer(tmp_path: Path) -> None:
    """API 'read-only' helper shares access mode with writers (in-process safe)."""
    config = _full_config(tmp_path)
    _seed_empty_warehouse(config)
    writer = get_connection(config)
    try:
        reader = get_read_only_connection(config)
        try:
            assert reader.execute("SELECT 1").fetchone()[0] == 1
        finally:
            reader.close()
    finally:
        writer.close()


def test_pipeline_imports_without_api_package() -> None:
    """Core pipeline module must import even if FastAPI is present; API is separate."""
    from src import pipeline

    assert hasattr(pipeline, "main")


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ts_key(value: datetime) -> str:
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(timespec="seconds")


def test_timeline_newest_default_without_window(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    origin = datetime(2024, 1, 1, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [origin, origin],
        )
        for index in range(500):
            ts = origin + timedelta(minutes=index)
            conn.execute(
                """
                INSERT INTO parsed_events
                (event_id, entity_id, event_timestamp, log_source, raw_fields, ingested_at)
                VALUES (?, 'alice', ?, 'ssh', '{}'::JSON, ?)
                """,
                [index + 1, ts, ts],
            )
        latest_rows = conn.execute(
            """
            SELECT event_timestamp FROM parsed_events
            WHERE entity_id = 'alice'
            ORDER BY event_timestamp DESC
            LIMIT 10
            """
        ).fetchall()
    finally:
        conn.close()
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    response = client.get("/api/entities/alice/timeline?limit=10")
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 10
    got = [_ts_key(_parse_ts(item["event_timestamp"])) for item in events]
    expected = [_ts_key(row[0]) for row in latest_rows]
    assert got == expected


def test_timeline_start_end_filters_range(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    origin = datetime(2024, 1, 1, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [origin, origin],
        )
        for index in range(20):
            ts = origin + timedelta(hours=index)
            conn.execute(
                """
                INSERT INTO parsed_events
                (event_id, entity_id, event_timestamp, log_source, raw_fields, ingested_at)
                VALUES (?, 'alice', ?, 'ssh', '{}'::JSON, ?)
                """,
                [index + 1, ts, ts],
            )
        bounds = conn.execute(
            """
            SELECT event_timestamp FROM parsed_events
            WHERE entity_id = 'alice'
            ORDER BY event_timestamp
            """
        ).fetchall()
        start = bounds[5][0]
        end = bounds[8][0]
        from src.api.queries import list_entity_timeline

        windowed = list_entity_timeline(
            conn, "alice", start=start, end=end, limit=100
        )
        assert len(windowed) == 4
        assert all(
            start <= ev.event_timestamp <= end for ev in windowed if ev.event_timestamp
        )
    finally:
        conn.close()
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    start_param = start.isoformat() if hasattr(start, "isoformat") else str(start)
    end_param = end.isoformat() if hasattr(end, "isoformat") else str(end)
    response = client.get(
        "/api/entities/alice/timeline",
        params={"start": start_param, "end": end_param},
    )
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 4


def test_html_entity_href_is_url_encoded(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice bob', 'user', ?, ?)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES (
              'inc-space', 'alice bob', ?, ?, 'low',
              'space in entity id',
              []
            )
            """,
            [start, end],
        )
    finally:
        conn.close()
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    response = client.get("/")
    assert response.status_code == 200
    assert "/entities/alice%20bob" in response.text
    assert 'href="/entities/alice bob"' not in response.text


def test_incident_detail_includes_precedes(seeded_client: TestClient) -> None:
    detail = seeded_client.get("/incidents/inc-1")
    assert detail.status_code == 200
    assert "precedes" in detail.text
    assert "start=" in detail.text
    assert "Statistical flags high rate only" in detail.text


def test_incident_pagination_second_page(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    origin = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [origin, origin],
        )
        for index in range(120):
            conn.execute(
                """
                INSERT INTO incidents
                (incident_id, entity_id, start_time, end_time, severity,
                 summary_text, contributing_anomaly_ids)
                VALUES (?, 'alice', ?, ?, 'low', 'bulk seed', [])
                """,
                [f"inc-{index:03d}", origin, origin],
            )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    page1 = client.get("/")
    page2 = client.get("/?page=2")
    assert page1.status_code == 200
    assert page2.status_code == 200
    assert "Showing 1–50 of 120" in page1.text
    assert "Showing 51–100 of 120" in page2.text
    assert "inc-000" in page1.text
    assert "inc-000" not in page2.text
    assert "inc-050" in page2.text
    assert "inc-050" not in page1.text


def test_html_entity_start_end_filters_range(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    origin = datetime(2024, 1, 1, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [origin, origin],
        )
        for index in range(20):
            ts = origin + timedelta(hours=index)
            conn.execute(
                """
                INSERT INTO parsed_events
                (event_id, entity_id, event_timestamp, log_source, raw_fields, ingested_at)
                VALUES (?, 'alice', ?, 'ssh', ?::JSON, ?)
                """,
                [index + 1, ts, f'{{"tag": "hour-{index}"}}', ts],
            )
        bounds = conn.execute(
            """
            SELECT event_timestamp FROM parsed_events
            WHERE entity_id = 'alice'
            ORDER BY event_timestamp
            """
        ).fetchall()
        start = bounds[5][0]
        end = bounds[8][0]
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    start_param = start.isoformat() if hasattr(start, "isoformat") else str(start)
    end_param = end.isoformat() if hasattr(end, "isoformat") else str(end)
    response = client.get(
        "/entities/alice",
        params={"start": start_param, "end": end_param},
    )
    assert response.status_code == 200
    assert "hour-5" in response.text
    assert "hour-8" in response.text
    assert "hour-0" not in response.text
    assert "hour-19" not in response.text


def test_vendor_chartjs_served_locally(seeded_client: TestClient) -> None:
    response = seeded_client.get("/static/vendor/chart.umd.min.js")
    assert response.status_code == 200
    body = response.text
    assert "Chart" in body
    html = seeded_client.get("/").text
    assert "fonts.googleapis.com" not in html
    assert "cdn.jsdelivr.net" not in html
    detail = seeded_client.get("/incidents/inc-1").text
    assert "fonts.googleapis.com" not in detail
    assert "cdn.jsdelivr.net" not in detail
    entity = seeded_client.get("/entities/alice").text
    assert "cdn.jsdelivr.net" not in entity


def test_kpi_critical_count(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    origin = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [origin, origin],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES
              ('inc-crit', 'alice', ?, ?, 'critical', 'critical seed', []),
              ('inc-high', 'alice', ?, ?, 'high', 'high seed', [])
            """,
            [origin, origin, origin, origin],
        )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    html = client.get("/").text
    match = re.search(
        r'kpi-label">Critical</span>\s*<span class="kpi-value">(\d+)</span>',
        html,
    )
    assert match is not None
    assert match.group(1) == "1"
    assert "inc-crit" in html
    assert "never" in html


def test_login_route_absent(seeded_client: TestClient) -> None:
    assert seeded_client.get("/login").status_code == 404


def test_entities_index_search(seeded_client: TestClient) -> None:
    response = seeded_client.get("/entities", params={"q": "ali"})
    assert response.status_code == 200
    assert "alice" in response.text


def test_api_incident_edges(seeded_client: TestClient) -> None:
    response = seeded_client.get("/api/incidents/inc-1/edges")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["relation_type"] == "precedes"
    assert items[0]["dst_anomaly_id"] == "anom-1"
    missing = seeded_client.get("/api/incidents/no-such/edges")
    assert missing.status_code == 404


def _client_report_dir(client: TestClient) -> Path:
    from src.config import load_config

    config = load_config(client.app.state.config_path)
    path = Path(config["paths"]["report_dir"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_reports_index_lists_incident_without_files(seeded_client: TestClient) -> None:
    response = seeded_client.get("/reports")
    assert response.status_code == 200
    assert "inc-1" in response.text
    assert "—" in response.text
    assert "Reports" in response.text


def test_report_file_serving_and_incident_link(seeded_client: TestClient) -> None:
    report_dir = _client_report_dir(seeded_client)
    html_name = "incident_inc-1.html"
    md_name = "incident_inc-1.md"
    (report_dir / html_name).write_text(
        "<!DOCTYPE html><p>report body</p>", encoding="utf-8"
    )
    (report_dir / md_name).write_text("# Incident Report\n", encoding="utf-8")

    listed = seeded_client.get("/reports")
    assert listed.status_code == 200
    assert f"/reports/{html_name}" in listed.text
    assert f"/reports/{md_name}" in listed.text

    html = seeded_client.get(f"/reports/{html_name}")
    assert html.status_code == 200
    assert "report body" in html.text

    md = seeded_client.get(f"/reports/{md_name}")
    assert md.status_code == 200
    assert "Incident Report" in md.text

    detail = seeded_client.get("/incidents/inc-1")
    assert detail.status_code == 200
    assert f'href="/reports/{html_name}"' in detail.text
    assert f'href="/reports/{md_name}"' in detail.text


def test_report_path_traversal_rejected(seeded_client: TestClient) -> None:
    assert seeded_client.get("/reports/../../etc/passwd").status_code in (400, 404)
    assert seeded_client.get("/reports/%2e%2e").status_code in (400, 404)
    assert seeded_client.get("/reports/%2e%2e%2fetc%2fpasswd").status_code in (400, 404)
    assert seeded_client.get("/reports/incident_../secret.html").status_code in (400, 404)
    missing = seeded_client.get("/reports/incident_missing.html")
    assert missing.status_code == 404
