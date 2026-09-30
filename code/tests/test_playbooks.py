"""Phase 62 playbooks: detector + ML model_type overlays."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.explainability.playbooks import (
    DEFAULT_PLAYBOOKS,
    load_playbooks,
    playbook_for,
    playbook_lookup_keys,
)
from src.explainability.payload import explanation_from_anomaly

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402
from src.db.connection import get_connection  # noqa: E402
from tests.test_api_dashboard import _full_config, _write_config  # noqa: E402

UTC = timezone.utc

REQUIRED_KEYS = (
    "statistical",
    "spectral",
    "ml",
    "autoencoder",
    "ensemble",
    "onnx",
    "cluster_outlier",
    "changepoint",
    "seasonal",
)


def test_default_playbooks_cover_phase62_keys() -> None:
    for key in REQUIRED_KEYS:
        assert key in DEFAULT_PLAYBOOKS
        payload = DEFAULT_PLAYBOOKS[key]
        assert payload["title"]
        assert payload["hint"]
        assert payload["actions"]


def test_load_playbooks_yaml_includes_new_keys() -> None:
    path = Path(__file__).resolve().parents[1] / "config" / "playbooks.yaml"
    loaded = load_playbooks(path)
    for key in REQUIRED_KEYS:
        assert key in loaded
        assert loaded[key]["title"]
    assert "reconstruction" in loaded["autoencoder"]["hint"].lower()
    assert "sidecar" in loaded["onnx"]["hint"].lower()
    assert "cusum" in loaded["changepoint"]["hint"].lower()
    assert "period_buckets" in loaded["seasonal"]["hint"]


def test_playbook_for_ml_resolves_model_type_overlays() -> None:
    ae = playbook_for("ml", model_type="autoencoder")
    assert ae is not None
    assert "reconstruction" in ae["title"].lower()

    onnx = playbook_for("ml", model_type="onnx")
    assert onnx is not None
    assert "onnx" in onnx["title"].lower()

    ensemble = playbook_for("ml", model_type="ensemble")
    assert ensemble is not None
    assert "ensemble" in ensemble["title"].lower()

    if_pb = playbook_for("ml", model_type="isolation_forest")
    assert if_pb is not None
    assert if_pb["title"] == DEFAULT_PLAYBOOKS["ml"]["title"]

    assert playbook_lookup_keys("ml", model_type="autoencoder") == [
        "autoencoder",
        "ml",
    ]
    assert playbook_lookup_keys("ml", model_type="ensemble") == [
        "ensemble",
        "ml",
    ]
    assert playbook_lookup_keys("changepoint") == ["changepoint"]


def test_playbook_for_missing_detector_returns_none() -> None:
    assert playbook_for("not_a_detector") is None


def test_explanation_uses_autoencoder_playbook_when_model_type_set() -> None:
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(hours=1)
    expl = explanation_from_anomaly(
        detector="ml",
        entity_id="alice",
        window_start=start,
        window_end=end,
        score=0.9,
        metadata={
            "model_type": "autoencoder",
            "flagging": "mad_threshold",
            "model_score": 0.9,
            "mad_z": 5.0,
            "mad_k": 4.0,
        },
    )
    assert expl["playbook"] is not None
    assert "reconstruction" in expl["playbook"]["title"].lower()
    assert expl["ml"]["model_type"] == "autoencoder"


def test_api_incident_shows_changepoint_playbook_title(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = start + timedelta(hours=6)
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
              'anom-cp', 'alice', ?, ?, 'changepoint', 6.2,
              '{"cusum_high": 6.2, "cusum_low": 0.0, "decision_h": 5.0,
                "drift_k": 0.5, "direction": "up",
                "rule": "cusum_sigma >= decision_h"}'::JSON
            )
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-cp', 'alice', ?, ?, 'medium', 'level shift', ?)
            """,
            [start, end, ["anom-cp"]],
        )
    finally:
        conn.close()

    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.get("/api/v1/incidents/inc-cp")
    assert response.status_code == 200
    expl = response.json()["anomalies"][0]["explanation"]
    assert expl["detector"] == "changepoint"
    assert expl["playbook"]["title"]
    assert "level shift" in expl["playbook"]["title"].lower()


def test_api_incident_shows_onnx_playbook_title(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    start = datetime(2024, 1, 2, tzinfo=UTC)
    end = start + timedelta(hours=1)
    conn = get_connection(config)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('bob', 'user', ?, ?)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end,
             source_detector, score, metadata)
            VALUES (
              'anom-onnx', 'bob', ?, ?, 'ml', 0.88,
              '{"model_type": "onnx", "flagging": "mad_threshold",
                "model_score": 0.88, "mad_z": 4.5, "mad_k": 4.0}'::JSON
            )
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-onnx', 'bob', ?, ?, 'low', 'onnx flag', ?)
            """,
            [start, end, ["anom-onnx"]],
        )
    finally:
        conn.close()

    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.get("/api/v1/incidents/inc-onnx")
    assert response.status_code == 200
    expl = response.json()["anomalies"][0]["explanation"]
    assert expl["ml"]["model_type"] == "onnx"
    assert expl["playbook"]["title"]
    assert "onnx" in expl["playbook"]["title"].lower()
