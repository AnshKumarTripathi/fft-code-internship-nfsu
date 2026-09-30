"""Phase 91 — sharded pipeline job API: start, status shape, cancel, busy 409."""

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
from src.ingestion.sharding.orchestrate import ShardedIngestParseResult  # noqa: E402
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


def _client(tmp_path: Path, *, sharding_enabled: bool = True) -> TestClient:
    config = _full_config(tmp_path)
    raw = Path(config["paths"]["raw_log_dir"])
    raw.mkdir(parents=True, exist_ok=True)
    shards = raw / "shards"
    shards.mkdir(parents=True, exist_ok=True)
    uploads = raw / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    config["pipeline_ui"] = {
        "upload_dir": str(uploads),
        "max_upload_bytes": 52_428_800,
        "max_files_per_request": 50,
        "allowed_suffixes": [".log", ".txt"],
    }
    config["sharding"] = {
        "enabled": sharding_enabled,
        "target_shard_bytes": 200,
        "target_shard_lines": None,
        "output_dir": str(shards),
        "max_shards": 50,
        "prefer_server_path": True,
        "analysis_window": {"enabled": False, "last_days": 30},
    }
    config["paths"]["analyses_dir"] = str(Path(config["paths"]["db_path"]).parent / "analyses")
    _seed_empty_warehouse(config)
    return TestClient(create_app(_write_config(tmp_path, config)))


def _write_huge_like(raw: Path, name: str = "huge.log") -> Path:
    path = raw / name
    path.write_text(
        "\n".join(f"line {i} auth ok user=alice" for i in range(40)) + "\n",
        encoding="utf-8",
    )
    return path


def _wait_terminal(
    client: TestClient,
    job_id: str,
    timeout: float = 5.0,
    *,
    terminals: frozenset[str] | None = None,
) -> dict:
    done = terminals or frozenset({"succeeded", "failed", "cancelled"})
    deadline = time.time() + timeout
    body: dict[str, Any] = {}
    while time.time() < deadline:
        response = client.get(f"/api/v1/pipeline/jobs/{job_id}")
        assert response.status_code == 200
        body = response.json()
        if body["status"] in done:
            get_job_store().wait(job_id, timeout=1.0)
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish: {body}")


def test_sharding_settings_endpoint(tmp_path: Path) -> None:
    client = _client(tmp_path, sharding_enabled=True)
    response = client.get("/api/v1/pipeline/sharding")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["prefer_server_path"] is True
    assert body["max_upload_bytes"] == 52_428_800
    assert body["max_shards"] == 50


def test_sharded_job_rejected_when_disabled(tmp_path: Path) -> None:
    client = _client(tmp_path, sharding_enabled=False)
    settings = client.get("/api/v1/pipeline/sharding").json()
    assert settings["enabled"] is False
    path = _write_huge_like(Path(settings["raw_log_dir"]))
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_sharded",
            "label": "disabled shard",
            "input_path": str(path),
        },
    )
    assert created.status_code == 422
    assert "sharding.enabled" in created.json()["detail"]


def test_sharded_job_status_shape_and_progress(tmp_path: Path, monkeypatch) -> None:
    gate = threading.Event()
    progress_seen: list[tuple] = []

    def _fake_pipeline(
        config: dict[str, Any],
        *,
        config_path: str | None = None,
        through: str = "report",
        manifest_path=None,
        input_path=None,
        split_run_id=None,
        require_complete: bool = False,
        on_progress=None,
        on_stage=None,
        should_cancel=None,
    ) -> ShardedIngestParseResult:
        _ = (
            config,
            config_path,
            through,
            manifest_path,
            split_run_id,
            require_complete,
        )
        assert input_path is not None
        if on_progress:
            on_progress("split", None, 3, "manifest ready")
            progress_seen.append(("split", 3))
            on_progress("ingest_parse", 0, 3, "ingest shard 1/3")
            progress_seen.append(("ingest_parse", 0))
        gate.wait(timeout=2.0)
        if on_progress:
            on_progress("ingest_parse", 1, 3, "ingest shard 2/3")
            on_progress("detect", None, 3, "post-merge")
        if on_stage:
            on_stage("bucket", "running", None)
            on_stage("bucket", "success", None)
            on_stage("correlate", "running", None)
            on_stage("correlate", "success", None)
        return ShardedIngestParseResult(
            split_run_id="demo",
            shard_count=3,
            corpus_digest="abc",
            post_merge_exit_code=0,
            post_merge_ran=True,
        )

    monkeypatch.setattr(
        "src.api.pipeline_jobs.run_sharded_pipeline",
        _fake_pipeline,
    )

    client = _client(tmp_path)
    settings = client.get("/api/v1/pipeline/sharding").json()
    path = _write_huge_like(Path(settings["raw_log_dir"]))

    created = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_sharded",
            "label": "shard demo",
            "input_path": str(path),
        },
    )
    assert created.status_code == 202, created.text
    body = created.json()
    job_id = body["job_id"]
    assert body["mode"] == "run_sharded"
    assert body["cancel_supported"] is True
    assert body["input_path"] == str(path.resolve())
    assert "shard_index" in body
    assert "shard_count" in body
    assert "phase" in body
    assert body["stages"][0]["stage"] == "split"
    assert body["stages"][1]["stage"] == "ingest_parse"

    deadline = time.time() + 2.0
    mid_body: dict[str, Any] = {}
    while time.time() < deadline:
        mid = client.get(f"/api/v1/pipeline/jobs/{job_id}")
        mid_body = mid.json()
        if mid_body.get("phase") == "ingest_parse" and mid_body.get("shard_count") == 3:
            break
        time.sleep(0.01)
    assert mid_body["status"] in {"running", "cancelling"}
    assert mid_body["shard_count"] == 3
    assert mid_body["shard_index"] == 0
    assert mid_body["phase"] == "ingest_parse"

    gate.set()
    final = _wait_terminal(client, job_id)
    assert final["status"] == "succeeded"
    assert final["shard_count"] == 3
    assert final["phase"] == "done"
    assert progress_seen


def test_cancel_between_shards(tmp_path: Path, monkeypatch) -> None:
    started = threading.Event()
    release = threading.Event()

    def _fake_pipeline(
        config: dict[str, Any],
        *,
        config_path: str | None = None,
        through: str = "report",
        manifest_path=None,
        input_path=None,
        split_run_id=None,
        require_complete: bool = False,
        on_progress=None,
        on_stage=None,
        should_cancel=None,
    ) -> ShardedIngestParseResult:
        _ = config, config_path, through, manifest_path, input_path, split_run_id
        _ = require_complete, on_stage
        if on_progress:
            on_progress("ingest_parse", 0, 4, "shard 1/4")
        started.set()
        # Hold until cancel is requested, then honour should_cancel.
        release.wait(timeout=3.0)
        if should_cancel and should_cancel():
            if on_progress:
                on_progress("ingest_parse", 0, 4, "cancelled")
            result = ShardedIngestParseResult(split_run_id="x", shard_count=4)
            result.cancelled = True
            result.cancel_message = (
                "Cancelled between shards after 1/4 "
                "(current shard may have finished; detect not started)"
            )
            return result
        raise AssertionError("expected cancel")

    monkeypatch.setattr(
        "src.api.pipeline_jobs.run_sharded_pipeline",
        _fake_pipeline,
    )

    client = _client(tmp_path)
    settings = client.get("/api/v1/pipeline/sharding").json()
    path = _write_huge_like(Path(settings["raw_log_dir"]))
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_sharded",
            "label": "cancel me",
            "input_path": str(path),
        },
    )
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    assert started.wait(timeout=2.0)

    cancel = client.post(f"/api/v1/pipeline/jobs/{job_id}/cancel")
    assert cancel.status_code == 200
    assert cancel.json()["cancel_requested"] is True
    assert cancel.json()["status"] in {"cancelling", "running", "cancelled"}

    release.set()
    final = _wait_terminal(client, job_id)
    assert final["status"] == "cancelled"
    assert "detect not started" in (final["error"] or "")
    assert final["phase"] == "cancelled"


def test_sharded_and_normal_share_single_flight_409(
    tmp_path: Path, monkeypatch
) -> None:
    block = threading.Event()

    def _block(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        block.wait(timeout=5.0)

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
        json={"mode": "run_all", "stages": ["ingest"], "label": "hold"},
    )
    assert first.status_code == 202
    job_id = first.json()["job_id"]

    deadline = time.time() + 2.0
    while time.time() < deadline:
        if client.get(f"/api/v1/pipeline/jobs/{job_id}").json()["status"] == "running":
            break
        time.sleep(0.01)

    settings = client.get("/api/v1/pipeline/sharding").json()
    path = _write_huge_like(Path(settings["raw_log_dir"]))
    second = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_sharded",
            "label": "should 409",
            "input_path": str(path),
        },
    )
    assert second.status_code == 409
    block.set()
    _wait_terminal(client, job_id)


def test_cancel_rejected_for_run_all(tmp_path: Path, monkeypatch) -> None:
    block = threading.Event()

    def _block(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        block.wait(timeout=5.0)

    monkeypatch.setitem(STAGE_HANDLERS, "ingest", _block)
    for stage in STAGE_ORDER:
        if stage != "ingest":
            monkeypatch.setitem(
                STAGE_HANDLERS,
                stage,
                lambda config, config_path=None: None,
            )

    client = _client(tmp_path)
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["ingest"], "label": "no cancel"},
    )
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if client.get(f"/api/v1/pipeline/jobs/{job_id}").json()["status"] == "running":
            break
        time.sleep(0.01)

    cancel = client.post(f"/api/v1/pipeline/jobs/{job_id}/cancel")
    assert cancel.status_code == 422
    block.set()
    _wait_terminal(client, job_id)


def test_use_staged_uploads_requires_exactly_one(tmp_path: Path) -> None:
    client = _client(tmp_path)
    settings = client.get("/api/v1/pipeline/sharding").json()
    upload_dir = Path(settings["raw_log_dir"]) / "uploads"
    (upload_dir / "a.log").write_text("one\n", encoding="utf-8")
    (upload_dir / "b.log").write_text("two\n", encoding="utf-8")

    created = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_sharded",
            "label": "two staged",
            "use_staged_uploads": True,
        },
    )
    assert created.status_code == 422
    assert "exactly one" in created.json()["detail"]


def test_path_outside_raw_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    outside = tmp_path / "outside.log"
    outside.write_text("nope\n", encoding="utf-8")
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={
            "mode": "run_sharded",
            "label": "outside",
            "input_path": str(outside),
        },
    )
    assert created.status_code == 422
    assert "raw_log_dir" in created.json()["detail"]


def test_orchestrator_cancel_between_shards(tmp_path: Path) -> None:
    """Cancel check before shard i+1 marks the result cancelled (no detect)."""
    from src.ingestion.sharding.orchestrate import run_sharded_pipeline

    config = _full_config(tmp_path)
    raw = Path(config["paths"]["raw_log_dir"])
    raw.mkdir(parents=True)
    shards = raw / "shards"
    shards.mkdir(parents=True)
    config["sharding"] = {
        "enabled": True,
        "target_shard_bytes": 80,
        "target_shard_lines": None,
        "output_dir": str(shards),
        "max_shards": 50,
        "prefer_server_path": True,
        "analysis_window": {"enabled": False, "last_days": 30},
    }
    config["parse"] = {
        "mode": "train_and_snapshot",
        "start_empty": True,
        "snapshot_id": None,
    }
    # Force cancel before the first shard starts (between "shards" gate).
    calls = {"n": 0}

    def should_cancel() -> bool:
        calls["n"] += 1
        return True

    source = _write_huge_like(raw)
    result = run_sharded_pipeline(
        config,
        through="report",
        input_path=source,
        should_cancel=should_cancel,
    )
    assert result.cancelled is True
    assert result.post_merge_ran is False
    assert result.shard_statuses == []
    assert calls["n"] >= 1
