"""Phase 56: pipeline job API — start, poll, single-flight 409."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402
from src.api.pipeline_jobs import get_job_store, reset_job_store  # noqa: E402
from src.correlation.merge_scores import NothingToCorrelate  # noqa: E402
from src.pipeline import STAGE_HANDLERS, STAGE_ORDER  # noqa: E402
from tests.test_api_dashboard import (  # noqa: E402
    _full_config,
    _seed_empty_warehouse,
    _write_config,
)


@pytest.fixture(autouse=True)
def _clean_job_store() -> None:
    reset_job_store()
    yield
    store = get_job_store()
    latest = store.latest()
    if latest is not None:
        store.wait(latest.job_id, timeout=5.0)
    reset_job_store()


def _client(tmp_path: Path) -> TestClient:
    config = _full_config(tmp_path)
    _seed_empty_warehouse(config)
    return TestClient(create_app(_write_config(tmp_path, config)))


def _wait_terminal(client: TestClient, job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    body: dict[str, Any] = {}
    while time.time() < deadline:
        response = client.get(f"/api/v1/pipeline/jobs/{job_id}")
        assert response.status_code == 200
        body = response.json()
        if body["status"] in {"succeeded", "failed"}:
            get_job_store().wait(job_id, timeout=1.0)
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish: {body}")


def test_post_starts_job_and_poll_shows_progress(tmp_path: Path, monkeypatch) -> None:
    gate = threading.Event()
    seen: list[str] = []

    def _slow_ok(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        seen.append("running")
        gate.wait(timeout=2.0)
        seen.append("done")

    monkeypatch.setitem(STAGE_HANDLERS, "ingest", _slow_ok)
    for stage in STAGE_ORDER:
        if stage == "ingest":
            continue
        monkeypatch.setitem(
            STAGE_HANDLERS,
            stage,
            lambda config, config_path=None, _s=stage: None,
        )

    client = _client(tmp_path)
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={"mode": "run_all", "stages": ["ingest", "parse"]},
    )
    assert created.status_code == 202
    body = created.json()
    job_id = body["job_id"]
    assert body["status"] in {"queued", "running"}
    assert body["total_stages"] == 2
    assert [row["stage"] for row in body["stages"]] == ["ingest", "parse"]

    # Hold ingest until we observe running, then release.
    deadline = time.time() + 2.0
    while time.time() < deadline and "running" not in seen:
        time.sleep(0.01)
    mid = client.get(f"/api/v1/pipeline/jobs/{job_id}")
    assert mid.status_code == 200
    mid_body = mid.json()
    assert mid_body["status"] == "running"
    assert mid_body["current_stage"] == "ingest"
    assert mid_body["stages"][0]["status"] == "running"

    gate.set()
    final = _wait_terminal(client, job_id)
    assert final["status"] == "succeeded"
    assert final["completed_stages"] == 2
    assert final["current_stage"] is None
    assert [row["status"] for row in final["stages"]] == ["success", "success"]

    latest = client.get("/api/v1/pipeline/jobs")
    assert latest.status_code == 200
    assert latest.json()["job_id"] == job_id


def test_second_concurrent_start_returns_409(tmp_path: Path, monkeypatch) -> None:
    release = threading.Event()

    def _block(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        release.wait(timeout=5.0)

    monkeypatch.setitem(STAGE_HANDLERS, "ingest", _block)
    for stage in STAGE_ORDER:
        if stage != "ingest":
            monkeypatch.setitem(
                STAGE_HANDLERS,
                stage,
                lambda config, config_path=None: None,
            )

    client = _client(tmp_path)
    first = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["ingest"]},
    )
    assert first.status_code == 202
    job_id = first.json()["job_id"]

    # Ensure the runner has marked the job running before the second POST.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        status = client.get(f"/api/v1/pipeline/jobs/{job_id}").json()["status"]
        if status == "running":
            break
        time.sleep(0.01)

    second = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["ingest"]},
    )
    assert second.status_code == 409
    detail = second.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["job_id"] == job_id
    assert "already running" in detail["message"].lower()

    release.set()
    _wait_terminal(client, job_id)


def test_failed_stage_marks_job_failed(tmp_path: Path, monkeypatch) -> None:
    def _boom(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        raise RuntimeError("synthetic stage failure")

    monkeypatch.setitem(STAGE_HANDLERS, "parse", _boom)
    monkeypatch.setitem(
        STAGE_HANDLERS,
        "ingest",
        lambda config, config_path=None: None,
    )

    client = _client(tmp_path)
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["ingest", "parse"]},
    )
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    final = _wait_terminal(client, job_id)
    assert final["status"] == "failed"
    assert "parse" in (final["error"] or "")
    statuses = {row["stage"]: row["status"] for row in final["stages"]}
    assert statuses["ingest"] == "success"
    assert statuses["parse"] == "failed"
    assert final["stages"][1]["detail"]
    assert "synthetic stage failure" in final["stages"][1]["detail"]


def test_soft_skip_counts_as_completed_unless_require_complete(
    tmp_path: Path, monkeypatch
) -> None:
    def _noop(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path

    def _skip_correlate(
        config: dict[str, Any], config_path: str | None = None
    ) -> None:
        _ = config, config_path
        raise NothingToCorrelate("no flagged sources")

    monkeypatch.setitem(STAGE_HANDLERS, "ingest", _noop)
    monkeypatch.setitem(STAGE_HANDLERS, "correlate", _skip_correlate)

    client = _client(tmp_path)
    soft = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["ingest", "correlate"], "require_complete": False},
    )
    soft_id = soft.json()["job_id"]
    soft_final = _wait_terminal(client, soft_id)
    assert soft_final["status"] == "succeeded"
    assert soft_final["completed_stages"] == 2
    assert soft_final["stages"][1]["status"] == "skipped"

    strict = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["ingest", "correlate"], "require_complete": True},
    )
    strict_id = strict.json()["job_id"]
    strict_final = _wait_terminal(client, strict_id)
    assert strict_final["status"] == "failed"
    assert "require-complete" in (strict_final["error"] or "").lower()


def test_unknown_stage_and_missing_job(tmp_path: Path) -> None:
    client = _client(tmp_path)
    bad = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["not-a-stage"]},
    )
    assert bad.status_code == 422

    missing = client.get("/api/v1/pipeline/jobs/does-not-exist")
    assert missing.status_code == 404

    empty = client.get("/api/v1/pipeline/jobs")
    assert empty.status_code == 404


def test_ml_ensemble_enabled_override_reaches_detect_ml(
    tmp_path: Path, monkeypatch
) -> None:
    seen: dict[str, Any] = {}

    def _capture_ml(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config_path
        ensemble = (config.get("ml") or {}).get("ensemble") or {}
        seen["enabled"] = ensemble.get("enabled")

    monkeypatch.setitem(STAGE_HANDLERS, "detect-ml", _capture_ml)
    for stage in STAGE_ORDER:
        if stage == "detect-ml":
            continue
        monkeypatch.setitem(
            STAGE_HANDLERS,
            stage,
            lambda config, config_path=None, _s=stage: None,
        )

    client = _client(tmp_path)
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["detect-ml"], "ml_ensemble_enabled": True},
    )
    assert created.status_code == 202
    body = created.json()
    assert body["ml_ensemble_enabled"] is True
    final = _wait_terminal(client, body["job_id"])
    assert final["status"] == "succeeded"
    assert seen.get("enabled") is True
