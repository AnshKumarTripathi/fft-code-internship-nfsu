"""Phase 65: analyses API — create, list, bind on job start, finalize on finish."""

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
            get_job_store().wait(job_id, timeout=2.0)
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish: {body}")


def _wait_analysis_status(
    client: TestClient,
    analysis_id: str,
    expected: str,
    timeout: float = 5.0,
) -> dict:
    deadline = time.time() + timeout
    body: dict[str, Any] = {}
    while time.time() < deadline:
        response = client.get(f"/api/v1/analyses/{analysis_id}")
        assert response.status_code == 200
        body = response.json()
        if body["status"] == expected:
            return body
        time.sleep(0.05)
    raise AssertionError(
        f"analysis {analysis_id} status not {expected}: {body}"
    )


def _stub_fast_stages(monkeypatch) -> None:
    for stage in STAGE_ORDER:
        monkeypatch.setitem(
            STAGE_HANDLERS,
            stage,
            lambda config, config_path=None, _s=stage: None,
        )


def test_create_list_get_patch_analysis(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/api/v1/analyses",
        json={"label": "SSH lab · afternoon", "notes": "mentor demo"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["label"] == "SSH lab · afternoon"
    assert body["status"] == "draft"
    assert body["notes"] == "mentor demo"
    analysis_id = body["analysis_id"]

    listed = client.get("/api/v1/analyses")
    assert listed.status_code == 200
    envelope = listed.json()
    assert envelope["total"] >= 1
    assert any(item["analysis_id"] == analysis_id for item in envelope["items"])

    detail = client.get(f"/api/v1/analyses/{analysis_id}")
    assert detail.status_code == 200
    assert detail.json()["label"] == "SSH lab · afternoon"

    patched = client.patch(
        f"/api/v1/analyses/{analysis_id}",
        json={"label": "SSH lab · renamed"},
    )
    assert patched.status_code == 200
    assert patched.json()["label"] == "SSH lab · renamed"


def test_create_requires_label(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post("/api/v1/analyses", json={"label": "  "})
    assert response.status_code == 422


def test_job_start_binds_analysis_and_finalizes(tmp_path: Path, monkeypatch) -> None:
    _stub_fast_stages(monkeypatch)
    client = _client(tmp_path)

    seeded = client.post("/api/v1/pipeline/corpus/demo")
    assert seeded.status_code == 201
    assert len(seeded.json()["files"]) >= 1

    created = client.post(
        "/api/v1/analyses",
        json={"label": "Bind me"},
    )
    assert created.status_code == 201
    analysis_id = created.json()["analysis_id"]

    started = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_all",
            "analysis_id": analysis_id,
            "stages": ["ingest", "parse"],
        },
    )
    assert started.status_code == 202
    job = started.json()
    assert job["analysis_id"] == analysis_id

    bound = client.get(f"/api/v1/analyses/{analysis_id}")
    assert bound.status_code == 200
    bound_body = bound.json()
    assert bound_body["status"] == "running"
    assert bound_body["job_id"] == job["job_id"]
    assert bound_body["corpus_digest"]
    assert bound_body["file_count"] >= 1

    final = _wait_terminal(client, job["job_id"])
    assert final["status"] == "succeeded"

    ready = _wait_analysis_status(client, analysis_id, "ready")
    assert ready["status"] == "ready"


def test_job_start_auto_creates_analysis_from_label(
    tmp_path: Path, monkeypatch
) -> None:
    _stub_fast_stages(monkeypatch)
    client = _client(tmp_path)
    seeded = client.post("/api/v1/pipeline/corpus/demo")
    assert seeded.status_code == 201

    started = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_all",
            "label": "First attempt",
            "stages": ["ingest"],
        },
    )
    assert started.status_code == 202
    analysis_id = started.json()["analysis_id"]
    assert analysis_id

    _wait_terminal(client, started.json()["job_id"])

    second = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_all",
            "label": "Second attempt",
            "stages": ["ingest"],
        },
    )
    assert second.status_code == 202
    assert second.json()["analysis_id"] != analysis_id
    _wait_terminal(client, second.json()["job_id"])

    listed = client.get("/api/v1/analyses")
    assert listed.status_code == 200
    labels = {item["label"] for item in listed.json()["items"]}
    assert "First attempt" in labels
    assert "Second attempt" in labels


def test_job_failure_marks_analysis_failed(tmp_path: Path, monkeypatch) -> None:
    def _boom(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        raise RuntimeError("ingest exploded")

    monkeypatch.setitem(STAGE_HANDLERS, "ingest", _boom)
    for stage in STAGE_ORDER:
        if stage == "ingest":
            continue
        monkeypatch.setitem(
            STAGE_HANDLERS,
            stage,
            lambda config, config_path=None, _s=stage: None,
        )

    client = _client(tmp_path)
    seeded = client.post("/api/v1/pipeline/corpus/demo")
    assert seeded.status_code == 201

    started = client.post(
        "/api/v1/pipeline/jobs",
        json={"mode": "run_all", "label": "Will fail", "stages": ["ingest"]},
    )
    assert started.status_code == 202
    analysis_id = started.json()["analysis_id"]
    final = _wait_terminal(client, started.json()["job_id"])
    assert final["status"] == "failed"

    detail = _wait_analysis_status(client, analysis_id, "failed")
    assert detail["status"] == "failed"


def test_concurrent_bind_still_single_flight(tmp_path: Path, monkeypatch) -> None:
    release = threading.Event()

    def _block(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        release.wait(timeout=5.0)

    monkeypatch.setitem(STAGE_HANDLERS, "ingest", _block)
    for stage in STAGE_ORDER:
        if stage == "ingest":
            continue
        monkeypatch.setitem(
            STAGE_HANDLERS,
            stage,
            lambda config, config_path=None, _s=stage: None,
        )

    client = _client(tmp_path)
    seeded = client.post("/api/v1/pipeline/corpus/demo")
    assert seeded.status_code == 201

    first = client.post(
        "/api/v1/pipeline/jobs",
        json={"mode": "run_all", "label": "Hold", "stages": ["ingest"]},
    )
    assert first.status_code == 202
    second = client.post(
        "/api/v1/pipeline/jobs",
        json={"mode": "run_all", "label": "Blocked", "stages": ["ingest"]},
    )
    assert second.status_code == 409
    release.set()
    _wait_terminal(client, first.json()["job_id"])
