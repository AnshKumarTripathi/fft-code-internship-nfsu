"""Phase 37 `/api/v1` JSON contract tests (requires requirements-api.txt)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.api.main import create_app
from src.db.connection import get_connection

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_api_dashboard import (  # noqa: E402
    _full_config,
    _seed_incident_warehouse,
    _write_config,
)

ALLOWED_ORIGIN = "http://127.0.0.1:3000"


def _client(tmp_path: Path, *, seed: bool = True) -> TestClient:
    config = _full_config(tmp_path)
    if seed:
        _seed_incident_warehouse(config)
    else:
        conn = get_connection(config)
        conn.close()
    config_path = _write_config(tmp_path, config)
    return TestClient(create_app(config_path))


def _envelope_keys(body: dict) -> None:
    assert set(body) >= {"items", "total", "limit", "offset"}
    assert isinstance(body["items"], list)
    assert body["total"] >= len(body["items"])


def test_v1_incidents_envelope(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    body = response.json()
    _envelope_keys(body)
    assert body["total"] == 1
    assert body["items"][0]["incident_id"] == "inc-1"


def test_unversioned_incidents_still_bare_list(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/incidents")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert body[0]["incident_id"] == "inc-1"


def test_v1_incidents_pagination_pages_disjoint(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES ('alice', 'user', ?, ?, 'Alice')
            """,
            [start, start],
        )
        for index in range(120):
            conn.execute(
                """
                INSERT INTO incidents
                (incident_id, entity_id, start_time, end_time, severity,
                 summary_text, contributing_anomaly_ids)
                VALUES (?, 'alice', ?, ?, 'low', 'n', [])
                """,
                [f"page-{index:03d}", start, start + timedelta(hours=1)],
            )
    finally:
        conn.close()
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    first = client.get("/api/v1/incidents", params={"limit": 50, "offset": 0})
    second = client.get("/api/v1/incidents", params={"limit": 50, "offset": 50})
    assert first.status_code == 200
    assert second.status_code == 200
    first_ids = {item["incident_id"] for item in first.json()["items"]}
    second_ids = {item["incident_id"] for item in second.json()["items"]}
    assert first.json()["total"] == 120
    assert second.json()["total"] == 120
    assert first_ids.isdisjoint(second_ids)
    assert len(first_ids) == 50
    assert len(second_ids) == 50


def test_v1_incident_missing_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents/does-not-exist")
    assert response.status_code == 404


def test_v1_incident_detail_includes_anomalies(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents/inc-1")
    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "inc-1"
    assert isinstance(body["anomalies"], list)
    assert body["anomalies"][0]["anomaly_id"] == "anom-1"


def test_v1_incident_timeline_includes_log_source(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents/inc-1/timeline")
    assert response.status_code == 200
    body = response.json()
    _envelope_keys(body)
    assert body["items"][0]["log_source"] == "ssh"
    assert body["items"][0]["relation_type"] == "precedes"


def test_v1_incident_edges_include_log_source(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents/inc-1/edges")
    assert response.status_code == 200
    body = response.json()
    _envelope_keys(body)
    assert body["items"][0]["log_source"] == "ssh"


def test_cors_preflight_allows_local_origin(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.options(
        "/api/v1/incidents",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN


def test_cors_get_allows_local_origin(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get(
        "/api/v1/incidents",
        headers={"Origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN


def test_cors_does_not_reflect_unknown_origin(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get(
        "/api/v1/incidents",
        headers={"Origin": "http://evil.example"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") != "http://evil.example"


def test_v1_warehouse_busy_503(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import duckdb

    client = _client(tmp_path)

    def raise_lock(_config: dict) -> None:
        error_cls = getattr(duckdb, "IOException", duckdb.Error)
        raise error_cls("Could not set lock on file: warehouse.duckdb")

    monkeypatch.setattr("src.api.deps.get_read_only_connection", raise_lock)
    response = client.get("/api/v1/incidents")
    assert response.status_code == 503
    assert "detail" in response.json()


def test_v1_entities_search(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/entities", params={"q": "ali"})
    assert response.status_code == 200
    body = response.json()
    _envelope_keys(body)
    ids = {item["entity_id"] for item in body["items"]}
    assert "alice" in ids


def test_v1_entities_top_by_anomalies(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/entities/top", params={"limit": 5})
    assert response.status_code == 200
    body = response.json()
    _envelope_keys(body)
    assert body["items"]
    assert body["items"][0]["entity_id"] == "alice"
    assert body["items"][0]["anomaly_count"] >= 1
    assert "incident_count" in body["items"][0]


def test_v1_kpis_match_seed(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/kpis")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["critical"] == 0
    assert body["high"] == 1
    assert "last_report_at" in body
    assert body["detector_counts"]["statistical"] >= 1
    assert body["log_source_counts"][0]["log_source"] == "ssh"


def test_v1_incident_list_includes_detector_set(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["detector_set"] == ["statistical"]
    assert item["anomaly_count"] == 1


def test_v1_incident_detail_includes_edge_counts(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents/inc-1")
    assert response.status_code == 200
    body = response.json()
    assert body["edge_counts"]["precedes"] == 1
    assert body["has_ip_link"] is False
    assert body["anomalies_total"] == 1
    assert body["detector_set"] == ["statistical"]
    assert body["top_score"] == 5.2


def test_v1_incident_detail_caps_anomalies(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES ('bob', 'user', ?, ?, 'Bob')
            """,
            [start, start],
        )
        ids: list[str] = []
        for index in range(60):
            anomaly_id = f"cap-{index:03d}"
            ids.append(anomaly_id)
            conn.execute(
                """
                INSERT INTO anomaly_events
                (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
                VALUES (?, 'bob', ?, ?, 'ml', ?, '{}'::JSON)
                """,
                [anomaly_id, start, start + timedelta(hours=1), float(index)],
            )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-cap', 'bob', ?, ?, 'low', 'many', ?)
            """,
            [start, start + timedelta(hours=1), ids],
        )
    finally:
        conn.close()
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    response = client.get("/api/v1/incidents/inc-cap")
    assert response.status_code == 200
    body = response.json()
    assert body["anomalies_total"] == 60
    assert len(body["anomalies"]) == 50
    assert body["anomalies"][0]["score"] == 59.0


def test_v1_entity_buckets_include_overlays(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/entities/alice/buckets")
    assert response.status_code == 200
    body = response.json()
    _envelope_keys(body)
    assert "overlays" in body
    assert body["overlays"][0]["source"] == "spectral"
    assert body["bucket_seconds"] == 600


def test_v1_reports_traversal_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/reports/../pipeline.yaml")
    assert response.status_code == 404


def test_v1_reports_list_and_fetch(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    _seed_incident_warehouse(config)
    report_dir = Path(config["paths"]["report_dir"])
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "incident_inc-1.md").write_text("# inc-1\n", encoding="utf-8")
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    listed = client.get("/api/v1/reports")
    assert listed.status_code == 200
    body = listed.json()
    _envelope_keys(body)
    assert body["items"][0]["filename"] == "incident_inc-1.md"
    assert body["items"][0]["incident_id"] == "inc-1"
    fetched = client.get("/api/v1/reports/incident_inc-1.md")
    assert fetched.status_code == 200
    assert "inc-1" in fetched.text
    disposition = fetched.headers.get("content-disposition", "")
    assert "inline" in disposition.lower()


def test_no_login_route(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/login").status_code == 404


def test_openapi_lists_v1_incidents(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/v1/incidents" in paths


def test_negative_offset_422(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents", params={"offset": -1})
    assert response.status_code == 422


def test_v1_incidents_filter_by_start_after(tmp_path: Path) -> None:
    client = _client(tmp_path)
    too_late = client.get(
        "/api/v1/incidents",
        params={"start_after": "2024-01-02T00:00:00Z"},
    )
    assert too_late.status_code == 200
    assert too_late.json()["total"] == 0
    ok = client.get(
        "/api/v1/incidents",
        params={"start_after": "2024-01-01T00:00:00Z"},
    )
    assert ok.status_code == 200
    assert ok.json()["total"] == 1
    assert ok.json()["items"][0]["incident_id"] == "inc-1"


def test_v1_incidents_filter_by_end_before(tmp_path: Path) -> None:
    client = _client(tmp_path)
    too_early = client.get(
        "/api/v1/incidents",
        params={"end_before": "2024-01-01T12:30:00Z"},
    )
    assert too_early.status_code == 200
    assert too_early.json()["total"] == 0
    ok = client.get(
        "/api/v1/incidents",
        params={"end_before": "2024-01-01T14:00:00Z"},
    )
    assert ok.status_code == 200
    assert ok.json()["total"] == 1


def test_v1_incidents_filter_by_detector(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    _seed_incident_warehouse(config)
    conn = get_connection(config)
    start = datetime(2024, 1, 2, 12, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)
    try:
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
            VALUES ('anom-spec', 'alice', ?, ?, 'spectral', 6.0, '{}'::JSON)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-spec', 'alice', ?, ?, 'medium', 'shape', ['anom-spec'])
            """,
            [start, end],
        )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    spectral = client.get("/api/v1/incidents", params={"detector": "spectral"})
    assert spectral.status_code == 200
    assert spectral.json()["total"] == 1
    assert spectral.json()["items"][0]["incident_id"] == "inc-spec"
    statistical = client.get(
        "/api/v1/incidents", params={"detector": "statistical"}
    )
    assert statistical.status_code == 200
    assert statistical.json()["total"] == 1
    assert statistical.json()["items"][0]["incident_id"] == "inc-1"
    both = client.get(
        "/api/v1/incidents", params={"detector": "spectral,statistical"}
    )
    assert both.status_code == 200
    assert both.json()["total"] == 2


def test_v1_incidents_filter_min_detectors(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    _seed_incident_warehouse(config)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)
    try:
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
            VALUES
              ('anom-2', 'alice', ?, ?, 'spectral', 6.0, '{}'::JSON),
              ('anom-3', 'alice', ?, ?, 'ml', 4.5, '{}'::JSON)
            """,
            [start, end, start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES
              ('inc-multi', 'alice', ?, ?, 'critical', 'agree',
               ['anom-2', 'anom-3'])
            """,
            [start, end],
        )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    two = client.get("/api/v1/incidents", params={"min_detectors": 2})
    assert two.status_code == 200
    assert two.json()["total"] == 1
    assert two.json()["items"][0]["incident_id"] == "inc-multi"
    one = client.get("/api/v1/incidents", params={"min_detectors": 1})
    assert one.status_code == 200
    assert one.json()["total"] == 2


def test_v1_incidents_disposition_all_anomalies_rule(tmp_path: Path) -> None:
    client = _client(tmp_path)
    open_before = client.get(
        "/api/v1/incidents", params={"disposition": "open"}
    )
    assert open_before.status_code == 200
    assert open_before.json()["total"] == 1
    dismissed_before = client.get(
        "/api/v1/incidents", params={"disposition": "dismissed"}
    )
    assert dismissed_before.status_code == 200
    assert dismissed_before.json()["total"] == 0

    created = client.post(
        "/api/v1/actions",
        json={
            "incident_id": "inc-1",
            "anomaly_id": "anom-1",
            "action": "dismiss",
            "operator_label": "alice",
        },
    )
    assert created.status_code == 200

    dismissed = client.get(
        "/api/v1/incidents", params={"disposition": "dismissed"}
    )
    assert dismissed.status_code == 200
    assert dismissed.json()["total"] == 1
    assert dismissed.json()["items"][0]["incident_id"] == "inc-1"
    open_after = client.get(
        "/api/v1/incidents", params={"disposition": "open"}
    )
    assert open_after.status_code == 200
    assert open_after.json()["total"] == 0

    reopened = client.post(
        "/api/v1/actions",
        json={
            "incident_id": "inc-1",
            "anomaly_id": "anom-1",
            "action": "reopen",
            "operator_label": "alice",
        },
    )
    assert reopened.status_code == 200
    open_again = client.get(
        "/api/v1/incidents", params={"disposition": "open"}
    )
    assert open_again.status_code == 200
    assert open_again.json()["total"] == 1


def test_v1_incidents_sort_start_time(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    _seed_incident_warehouse(config)
    conn = get_connection(config)
    later = datetime(2024, 2, 1, 12, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-later', 'alice', ?, ?, 'low', 'later', [])
            """,
            [later, later + timedelta(hours=1)],
        )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    desc = client.get(
        "/api/v1/incidents",
        params={"sort": "start_time", "order": "desc"},
    )
    assert desc.status_code == 200
    ids = [item["incident_id"] for item in desc.json()["items"]]
    assert ids[0] == "inc-later"
    asc = client.get(
        "/api/v1/incidents",
        params={"sort": "start_time", "order": "asc"},
    )
    assert asc.status_code == 200
    ids_asc = [item["incident_id"] for item in asc.json()["items"]]
    assert ids_asc[0] == "inc-1"


def test_v1_incidents_default_params_unchanged(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["incident_id"] == "inc-1"
    assert body["items"][0]["detector_set"] == ["statistical"]


def test_v1_incidents_invalid_disposition_422(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get(
        "/api/v1/incidents", params={"disposition": "archived"}
    )
    assert response.status_code == 422
