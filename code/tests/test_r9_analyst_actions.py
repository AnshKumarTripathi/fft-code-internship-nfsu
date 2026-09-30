"""R9 analyst audit trail: append-only warehouse rows, API, reports."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402
from src.correlation.writers import clear_correlation_tables  # noqa: E402
from src.db.connection import get_connection  # noqa: E402
from src.reporting.report_generator import (
    IncidentRow,
    build_context,
    render_incident_markdown,
)
from tests.test_api_dashboard import (  # noqa: E402
    _full_config,
    _seed_incident_warehouse,
    _write_config,
)

UTC = timezone.utc
ALLOWED_ORIGIN = "http://127.0.0.1:3000"


def _client(tmp_path: Path) -> TestClient:
    config = _full_config(tmp_path)
    _seed_incident_warehouse(config)
    return TestClient(create_app(_write_config(tmp_path, config)))


def test_post_dismiss_writes_row_and_survives_get(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/api/v1/actions",
        json={
            "incident_id": "inc-1",
            "anomaly_id": "anom-1",
            "action": "dismiss",
            "note": "patch window",
            "operator_label": "alice",
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["action"] == "dismiss"
    assert body["operator_label"] == "alice"
    assert body["note"] == "patch window"
    assert body["anomaly_id"] == "anom-1"
    assert body["action_id"]

    listed = client.get("/api/v1/incidents/inc-1/actions")
    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["action_id"] == body["action_id"]

    detail = client.get("/api/v1/incidents/inc-1")
    assert detail.status_code == 200
    assert detail.json()["actions"][0]["action"] == "dismiss"


def test_default_operator_label_is_local(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/api/v1/actions",
        json={
            "incident_id": "inc-1",
            "anomaly_id": "anom-1",
            "action": "dismiss",
        },
    )
    assert created.status_code == 200
    assert created.json()["operator_label"] == "local"
    policy = client.get("/api/v1/ui-policy")
    assert policy.status_code == 200
    assert policy.json()["operator_label"] == "local"


def test_reopen_is_compensating_row_not_delete(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.post(
        "/api/v1/actions",
        json={
            "incident_id": "inc-1",
            "anomaly_id": "anom-1",
            "action": "dismiss",
            "operator_label": "alice",
        },
    )
    reopened = client.post(
        "/api/v1/actions",
        json={
            "incident_id": "inc-1",
            "anomaly_id": "anom-1",
            "action": "reopen",
            "note": "still suspicious",
            "operator_label": "alice",
        },
    )
    assert reopened.status_code == 200
    rows = client.get("/api/v1/incidents/inc-1/actions").json()
    assert [row["action"] for row in rows] == ["dismiss", "reopen"]
    deleted = client.delete(f"/api/v1/actions/{rows[0]['action_id']}")
    assert deleted.status_code in {404, 405, 422}


def test_note_requires_text_and_unknown_action_422(tmp_path: Path) -> None:
    client = _client(tmp_path)
    empty_note = client.post(
        "/api/v1/actions",
        json={"incident_id": "inc-1", "action": "note"},
    )
    assert empty_note.status_code == 422
    bad = client.post(
        "/api/v1/actions",
        json={"incident_id": "inc-1", "anomaly_id": "anom-1", "action": "delete"},
    )
    assert bad.status_code == 422
    missing = client.post(
        "/api/v1/actions",
        json={"incident_id": "no-such", "anomaly_id": "anom-1", "action": "dismiss"},
    )
    assert missing.status_code == 404


def test_dismiss_requires_contributing_anomaly(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/actions",
        json={
            "incident_id": "inc-1",
            "anomaly_id": "not-on-incident",
            "action": "dismiss",
        },
    )
    assert response.status_code == 422


def test_cors_preflight_allows_post_actions(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.options(
        "/api/v1/actions",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    allow_methods = response.headers.get("access-control-allow-methods", "")
    assert "POST" in allow_methods


def test_report_appendix_includes_actions(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(hours=1)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end,
             source_detector, score, metadata)
            VALUES ('anom-r9', 'alice', ?, ?, 'statistical', 5.0, '{}'::JSON)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-r9', 'alice', ?, ?, 'low', 'rate', ?)
            """,
            [start, end, ["anom-r9"]],
        )
        conn.execute(
            """
            INSERT INTO analyst_actions
            (action_id, incident_id, anomaly_id, action, note,
             operator_label, created_at, run_id)
            VALUES ('act-1', 'inc-r9', 'anom-r9', 'dismiss', 'change ticket',
                    'alice', ?, NULL)
            """,
            [start],
        )
        incident = IncidentRow(
            incident_id="inc-r9",
            entity_id="alice",
            start_time=start,
            end_time=end,
            severity="low",
            summary_text="rate",
            contributing_anomaly_ids=["anom-r9"],
        )
        context = build_context(conn, incident)
        markdown = render_incident_markdown(
            context, template_path=config["reporting"]["template_path"]
        )
    finally:
        conn.close()
    assert context["analyst_actions"][0]["action"] == "dismiss"
    assert "## Analyst actions" in markdown
    assert "change ticket" in markdown
    assert "alice" in markdown


def test_correlate_delete_keeps_analyst_actions(tmp_path: Path) -> None:
    client = _client(tmp_path)
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
    action_id = created.json()["action_id"]

    config = _full_config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = datetime(2024, 1, 1, 13, tzinfo=UTC)
    try:
        clear_correlation_tables(conn)
        remaining = conn.execute(
            "SELECT action_id, incident_id FROM analyst_actions"
        ).fetchall()
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-1', 'alice', ?, ?, 'low', 'rate', ['anom-1'])
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end,
             source_detector, score, metadata)
            VALUES ('anom-1', 'alice', ?, ?, 'statistical', 5.2, '{}'::JSON)
            """,
            [start, end],
        )
    finally:
        conn.close()

    assert remaining == [(action_id, "inc-1")]
    detail = client.get("/api/v1/incidents/inc-1")
    assert detail.status_code == 200
    assert detail.json()["actions"][0]["action_id"] == action_id
