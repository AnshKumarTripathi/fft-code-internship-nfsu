"""Phase 60 — capped STFT matrix API + unit caps."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from src.api.main import create_app
from src.db.connection import get_connection
from src.detectors.spectral.stft_matrix import (
    STFT_UI_MAX_FREQ_BINS,
    STFT_UI_MAX_TIME_BINS,
    compute_stft_power_matrix,
)

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_api_dashboard import _full_config, _write_config  # noqa: E402


def test_compute_stft_cap_enforced() -> None:
    n = 5000
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    starts = [start + timedelta(seconds=600 * i) for i in range(n)]
    counts = np.sin(np.linspace(0, 40 * np.pi, n)) + 2.0
    result = compute_stft_power_matrix(
        counts,
        starts,
        bucket_seconds=600,
        window_buckets=72,
        step_buckets=24,
        max_freq_bins=STFT_UI_MAX_FREQ_BINS,
        max_time_bins=STFT_UI_MAX_TIME_BINS,
    )
    assert result.empty_reason is None
    assert result.n_freq <= STFT_UI_MAX_FREQ_BINS
    assert result.n_time <= STFT_UI_MAX_TIME_BINS
    assert result.capped is True
    assert len(result.power) == result.n_freq
    assert all(len(row) == result.n_time for row in result.power)


def test_compute_stft_empty_entity() -> None:
    result = compute_stft_power_matrix(
        [],
        [],
        bucket_seconds=600,
        window_buckets=72,
        step_buckets=24,
    )
    assert result.empty_reason == "no_buckets"
    assert result.n_freq == 0
    assert result.power == []


def test_compute_stft_insufficient_history() -> None:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    starts = [start + timedelta(seconds=600 * i) for i in range(10)]
    result = compute_stft_power_matrix(
        [1.0] * 10,
        starts,
        bucket_seconds=600,
        window_buckets=72,
        step_buckets=24,
    )
    assert result.empty_reason == "insufficient_history"


def test_v1_entity_stft_endpoint(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    # Shorter STFT window so a modest seed is enough for the API path.
    config["spectral"]["window_hours"] = 2
    config["spectral"]["step_fraction"] = 0.5
    conn = get_connection(config)
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES ('bob', 'user', ?, ?, 'Bob')
            """,
            [start, start],
        )
        for index in range(200):
            conn.execute(
                """
                INSERT INTO entity_bucket_counts
                (entity_id, bucket_start, bucket_seconds, event_count)
                VALUES ('bob', ?, 600, ?)
                """,
                [
                    start + timedelta(seconds=600 * index),
                    float(2.0 + np.sin(index / 8.0)),
                ],
            )
    finally:
        conn.close()

    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    response = client.get("/api/v1/entities/bob/stft")
    assert response.status_code == 200
    body = response.json()
    assert body["entity_id"] == "bob"
    assert body["empty_reason"] is None
    assert body["n_freq"] > 0
    assert body["n_time"] > 0
    assert body["n_freq"] <= body["cap_max_freq"]
    assert body["n_time"] <= body["cap_max_time"]
    assert len(body["power"]) == body["n_freq"]


def test_v1_entity_stft_empty(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES ('empty', 'user', ?, ?, 'Empty')
            """,
            [start, start],
        )
    finally:
        conn.close()
    config_path = _write_config(tmp_path, config)
    client = TestClient(create_app(config_path))
    response = client.get("/api/v1/entities/empty/stft")
    assert response.status_code == 200
    body = response.json()
    assert body["empty_reason"] == "no_buckets"
    assert body["power"] == []
