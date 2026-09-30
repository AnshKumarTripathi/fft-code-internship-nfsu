"""R8 UI honesty: warn_band, uncertainty payload, ui-policy endpoint."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.explainability.payload import explanation_from_anomaly, uncertainty_band

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402
from src.db.connection import get_connection  # noqa: E402
from tests.test_api_dashboard import _full_config, _write_config  # noqa: E402

UTC = timezone.utc


def test_uncertainty_band_flagged_near_miss_below() -> None:
    flagged = uncertainty_band(4.2, 4.0, 0.5)
    assert flagged["band"] == "flagged"
    assert flagged["display"] == "4.2 ≥ 4.0"
    near = uncertainty_band(3.7, 4.0, 0.5)
    assert near["band"] == "near_miss"
    assert "near miss" in near["display"]
    quiet = uncertainty_band(2.0, 4.0, 0.5)
    assert quiet["band"] == "below"
    assert "4.0" in quiet["display"]


def test_explanation_includes_uncertainty() -> None:
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    expl = explanation_from_anomaly(
        detector="statistical",
        entity_id="alice",
        window_start=start,
        window_end=start + timedelta(hours=1),
        score=5.2,
        metadata={"rate_z": 5.2, "z_threshold": 4.0},
        warn_band=0.5,
    )
    assert expl["uncertainty"]["band"] == "flagged"
    assert expl["uncertainty"]["display"] == "5.2 ≥ 4.0"
    assert expl["uncertainty"]["warn_band"] == 0.5


def test_spectral_near_miss_uses_max_leg() -> None:
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    expl = explanation_from_anomaly(
        detector="spectral",
        entity_id="alice",
        window_start=start,
        window_end=start + timedelta(hours=72),
        score=3.8,
        metadata={
            "energy_z": 1.0,
            "shape_js_z": 3.8,
            "z_threshold": 4.0,
        },
        warn_band=0.5,
    )
    assert expl["uncertainty"]["band"] == "near_miss"
    assert expl["uncertainty"]["z"] == 3.8


def test_ui_policy_endpoint(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    config["explainability"] = {"warn_band": 0.25}
    conn = get_connection(config)
    conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.get("/api/v1/ui-policy")
    assert response.status_code == 200
    body = response.json()
    assert body["warn_band"] == 0.25
    assert body["statistical_z_threshold"] == 4.0
    assert body["spectral_z_threshold"] == 4.0
    assert body["ml_mad_k"] == 4.0


def test_api_incident_explanation_has_uncertainty(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(hours=1)
    conn = get_connection(config)
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
            VALUES (
              'anom-r8', 'alice', ?, ?, 'statistical', 4.1,
              '{"rate_z": 4.1, "z_threshold": 4.0}'::JSON
            )
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-r8', 'alice', ?, ?, 'medium', 'rate flag', ?)
            """,
            [start, end, ["anom-r8"]],
        )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.get("/api/v1/incidents/inc-r8")
    assert response.status_code == 200
    expl = response.json()["anomalies"][0]["explanation"]
    assert expl["uncertainty"]["band"] == "flagged"
    assert expl["uncertainty"]["display"] == "4.1 ≥ 4.0"
    assert expl["playbook"]["title"]


def test_spectrum_recent_scores_include_band(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = start + timedelta(hours=72)
    conn = get_connection(config)
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
            INSERT INTO spectral_baselines
            (entity_id, computed_at, bucket_seconds, nperseg, freq_grid, psd, psd_norm)
            VALUES ('alice', ?, 600, 64, [0.0, 0.1], [1.0, 1.0], [0.5, 0.5])
            """,
            [start],
        )
        conn.execute(
            """
            INSERT INTO entity_spectral_features
            (entity_id, dominant_period_hours, dominant_power_frac,
             spectral_entropy, total_power, computed_at)
            VALUES ('alice', 24.0, 0.4, 1.2, 10.0, ?)
            """,
            [start],
        )
        conn.execute(
            """
            INSERT INTO spectral_window_scores
            (entity_id, window_start, window_end, energy_z, shape_js_z, flagged)
            VALUES
              ('alice', ?, ?, 3.7, 1.0, FALSE),
              ('alice', ?, ?, 6.0, 2.0, TRUE)
            """,
            [start, end, start + timedelta(hours=24), end + timedelta(hours=24)],
        )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.get("/api/v1/entities/alice/spectrum")
    assert response.status_code == 200
    body = response.json()
    assert body["z_threshold"] == 4.0
    assert body["warn_band"] == 0.5
    bands = {row["band"] for row in body["recent_scores"]}
    assert "near_miss" in bands
    assert "flagged" in bands
    displays = {row["display"] for row in body["recent_scores"]}
    assert any("≥" in text or "near miss" in text for text in displays)
