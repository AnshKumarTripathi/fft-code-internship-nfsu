"""Phase 66: B2 triage snapshots — archive on finalize, read via analyses API."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.analyses import create_analysis, finalize_analysis_for_job, get_analysis
from src.api.analysis_snapshots import (
    read_triage_snapshot,
    triage_snapshot_path,
    write_triage_snapshot,
)
from src.api.main import create_app
from src.correlation.writers import clear_correlation_tables
from src.db.connection import get_connection
from tests.test_api_dashboard import (
    _full_config,
    _seed_incident_warehouse,
    _write_config,
)


def _with_analyses_dir(tmp_path: Path, config: dict) -> dict:
    config["paths"]["analyses_dir"] = str(tmp_path / "data" / "analyses")
    return config


def _client(tmp_path: Path, config: dict) -> TestClient:
    return TestClient(create_app(_write_config(tmp_path, config)))


def test_write_snapshot_survives_live_clear(tmp_path: Path) -> None:
    config = _with_analyses_dir(tmp_path, _full_config(tmp_path))
    _seed_incident_warehouse(config)

    conn = get_connection(config)
    try:
        analysis = create_analysis(conn, label="First run", status="draft")
        conn.execute(
            """
            UPDATE analyses
            SET status = 'ready',
                job_id = 'job-1',
                corpus_digest = 'abc123',
                file_count = 2,
                correlate_run_id = 'corr-1',
                updated_at = ?
            WHERE analysis_id = ?
            """,
            [datetime.now(timezone.utc), analysis.analysis_id],
        )
        analysis = get_analysis(conn, analysis.analysis_id)
        assert analysis is not None
        path = write_triage_snapshot(conn, analysis, config)
        assert path.is_file()

        live_before = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        assert live_before >= 1
        snapshot_ids = {
            row["incident_id"]
            for row in read_triage_snapshot(config, analysis.analysis_id)["incidents"]
        }
        assert snapshot_ids

        clear_correlation_tables(conn)
        live_after = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        assert live_after == 0
        analysis_id = analysis.analysis_id
    finally:
        conn.close()

    client = _client(tmp_path, config)
    response = client.get(f"/api/v1/analyses/{analysis_id}/incidents")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    returned = {item["incident_id"] for item in body["items"]}
    assert returned == snapshot_ids

    kpis = client.get(f"/api/v1/analyses/{analysis_id}/kpis")
    assert kpis.status_code == 200
    assert kpis.json()["total"] >= 1


def test_two_analyses_keep_distinct_snapshots(tmp_path: Path) -> None:
    config = _with_analyses_dir(tmp_path, _full_config(tmp_path))
    _seed_incident_warehouse(config)

    conn = get_connection(config)
    try:
        a1 = create_analysis(conn, label="Corpus A", status="ready")
        conn.execute(
            """
            UPDATE analyses
            SET correlate_run_id = 'c1', corpus_digest = 'd1', file_count = 1
            WHERE analysis_id = ?
            """,
            [a1.analysis_id],
        )
        a1 = get_analysis(conn, a1.analysis_id)
        assert a1 is not None
        write_triage_snapshot(conn, a1, config)
        first_ids = {
            row["incident_id"]
            for row in read_triage_snapshot(config, a1.analysis_id)["incidents"]
        }

        clear_correlation_tables(conn)
        start = datetime(2024, 2, 1, 12, tzinfo=timezone.utc)
        end = datetime(2024, 2, 1, 13, tzinfo=timezone.utc)
        existing = conn.execute(
            "SELECT 1 FROM entities WHERE entity_id = 'bob'"
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
                VALUES ('bob', 'user', ?, ?, 'Bob')
                """,
                [start, end],
            )
        conn.execute(
            """
            INSERT INTO incidents (
                incident_id, entity_id, start_time, end_time,
                severity, summary_text, contributing_anomaly_ids
            )
            VALUES ('inc-second', 'bob', ?, ?, 'high', 'Second run only', ?)
            """,
            [start, end, []],
        )

        a2 = create_analysis(conn, label="Corpus B", status="ready")
        conn.execute(
            """
            UPDATE analyses
            SET correlate_run_id = 'c2', corpus_digest = 'd2', file_count = 1
            WHERE analysis_id = ?
            """,
            [a2.analysis_id],
        )
        a2 = get_analysis(conn, a2.analysis_id)
        assert a2 is not None
        write_triage_snapshot(conn, a2, config)
        a1_id = a1.analysis_id
        a2_id = a2.analysis_id
    finally:
        conn.close()

    client = _client(tmp_path, config)
    first = client.get(f"/api/v1/analyses/{a1_id}/incidents").json()
    second = client.get(f"/api/v1/analyses/{a2_id}/incidents").json()
    first_returned = {item["incident_id"] for item in first["items"]}
    second_returned = {item["incident_id"] for item in second["items"]}
    assert first_returned == first_ids
    assert "inc-second" in second_returned
    assert "inc-second" not in first_returned


def test_finalize_writes_snapshot_when_correlate_present(tmp_path: Path) -> None:
    config = _with_analyses_dir(tmp_path, _full_config(tmp_path))
    _seed_incident_warehouse(config)

    conn = get_connection(config)
    try:
        analysis = create_analysis(conn, label="Snap on finalize", status="running")
        started = datetime(2024, 1, 1, 10, tzinfo=timezone.utc)
        finished = datetime(2024, 1, 1, 11, tzinfo=timezone.utc)
        conn.execute(
            """
            INSERT INTO pipeline_runs
            (run_id, stage, started_at, finished_at, status, params_json)
            VALUES ('corr-finalize', 'correlate', ?, ?, 'success', '{}')
            """,
            [started, finished],
        )
        updated = finalize_analysis_for_job(
            conn,
            analysis.analysis_id,
            job_succeeded=True,
            job_started_at=started,
            config=config,
        )
        assert updated is not None
        assert updated.status == "ready"
        assert updated.correlate_run_id == "corr-finalize"
        assert triage_snapshot_path(config, analysis.analysis_id).is_file()
    finally:
        conn.close()


def test_missing_snapshot_for_old_draft_returns_404(tmp_path: Path) -> None:
    config = _with_analyses_dir(tmp_path, _full_config(tmp_path))
    conn = get_connection(config)
    conn.close()
    client = _client(tmp_path, config)
    created = client.post("/api/v1/analyses", json={"label": "No snap"})
    assert created.status_code == 201
    analysis_id = created.json()["analysis_id"]
    response = client.get(f"/api/v1/analyses/{analysis_id}/incidents")
    assert response.status_code == 404
