"""Phase 57: pipeline upload / corpus select API."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402
from src.api.pipeline_jobs import reset_job_store  # noqa: E402
from src.config import ConfigError, load_config, pipeline_ui_settings  # noqa: E402
from src.ingestion.loaders import iter_raw_log_paths  # noqa: E402
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
    reset_job_store()


def _client(tmp_path: Path, *, max_upload_bytes: int | None = None) -> TestClient:
    config = _full_config(tmp_path)
    raw = Path(config["paths"]["raw_log_dir"])
    upload_dir = raw / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    config["pipeline_ui"] = {
        "upload_dir": str(upload_dir),
        "max_upload_bytes": max_upload_bytes or 52_428_800,
        "max_files_per_request": 50,
        "allowed_suffixes": [".log", ".txt", ".json", ".jsonl", ".csv"],
    }
    _seed_empty_warehouse(config)
    return TestClient(create_app(_write_config(tmp_path, config)))


def test_upload_list_delete_roundtrip(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = b"Failed password for alice from 10.0.0.1\n"
    created = client.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("auth.log", payload, "text/plain"))],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["upload_dir"].endswith("uploads") or "uploads" in body["upload_dir"]
    assert len(body["files"]) == 1
    item = body["files"][0]
    assert item["name"] == "auth.log"
    assert item["size_bytes"] == len(payload)
    assert item["sha256"] == hashlib.sha256(payload).hexdigest()
    assert item["modified_at"]

    listed = client.get("/api/v1/pipeline/uploads")
    assert listed.status_code == 200
    assert len(listed.json()["files"]) == 1
    assert listed.json()["files"][0]["sha256"] == item["sha256"]

    # Visible to ingest discovery under raw_log_dir.
    config = load_config(tmp_path / "pipeline.yaml")
    discovered = [path.name for path in iter_raw_log_paths(Path(config["paths"]["raw_log_dir"]))]
    assert "auth.log" in discovered

    deleted = client.delete("/api/v1/pipeline/uploads/auth.log")
    assert deleted.status_code == 204
    assert client.get("/api/v1/pipeline/uploads").json()["files"] == []


def test_reject_traversal_bad_suffix_and_oversize(tmp_path: Path) -> None:
    client = _client(tmp_path, max_upload_bytes=32)

    traversal = client.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("../evil.log", b"x" * 8, "text/plain"))],
    )
    assert traversal.status_code == 400
    assert "traversal" in traversal.json()["detail"].lower()

    bad_suffix = client.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("payload.exe", b"MZ", "application/octet-stream"))],
    )
    assert bad_suffix.status_code == 400
    assert "suffix" in bad_suffix.json()["detail"].lower()

    oversized = client.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("big.log", b"x" * 64, "text/plain"))],
    )
    assert oversized.status_code == 413
    assert client.get("/api/v1/pipeline/uploads").json()["files"] == []


def test_collision_gets_numeric_suffix(tmp_path: Path) -> None:
    client = _client(tmp_path)
    first = client.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("auth.log", b"one\n", "text/plain"))],
    )
    second = client.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("auth.log", b"two\n", "text/plain"))],
    )
    assert first.status_code == 201
    assert second.status_code == 201
    names = {row["name"] for row in client.get("/api/v1/pipeline/uploads").json()["files"]}
    assert names == {"auth.log", "auth_1.log"}


def test_demo_corpus_and_existing_raw_list(tmp_path: Path) -> None:
    client = _client(tmp_path)
    demo = client.post("/api/v1/pipeline/corpus/demo")
    assert demo.status_code == 201, demo.text
    files = demo.json()["files"]
    assert files
    assert all(row["sha256"] for row in files)

    # Top-level raw listing stays empty (demo lands under uploads/).
    raw_list = client.get("/api/v1/pipeline/corpus/raw")
    assert raw_list.status_code == 200
    assert raw_list.json()["mode"] == "existing_raw"
    assert raw_list.json()["files"] == []

    # Drop a top-level raw file and confirm listing.
    config = load_config(tmp_path / "pipeline.yaml")
    top = Path(config["paths"]["raw_log_dir"]) / "top.txt"
    top.write_text("hello\n", encoding="utf-8")
    raw_again = client.get("/api/v1/pipeline/corpus/raw")
    assert [row["name"] for row in raw_again.json()["files"]] == ["top.txt"]


def test_job_api_still_works_with_empty_uploads(tmp_path: Path, monkeypatch) -> None:
    for stage in STAGE_ORDER:
        monkeypatch.setitem(
            STAGE_HANDLERS,
            stage,
            lambda config, config_path=None: None,
        )
    client = _client(tmp_path)
    assert client.get("/api/v1/pipeline/uploads").json()["files"] == []
    created = client.post(
        "/api/v1/pipeline/jobs",
        json={"stages": ["ingest"]},
    )
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    # Poll briefly until terminal.
    import time

    deadline = time.time() + 5.0
    body = {}
    while time.time() < deadline:
        body = client.get(f"/api/v1/pipeline/jobs/{job_id}").json()
        if body["status"] in {"succeeded", "failed"}:
            break
        time.sleep(0.02)
    assert body["status"] == "succeeded"


def test_pipeline_ui_defaults_under_raw(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    path = tmp_path / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    loaded = load_config(path)
    settings = pipeline_ui_settings(loaded)
    assert Path(settings["upload_dir"]).resolve().is_relative_to(
        Path(loaded["paths"]["raw_log_dir"]).resolve()
    )


def test_pipeline_ui_rejects_upload_outside_raw(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    config["pipeline_ui"] = {
        "upload_dir": str(tmp_path / "elsewhere"),
        "max_upload_bytes": 1000,
        "max_files_per_request": 2,
        "allowed_suffixes": [".log"],
    }
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(ConfigError, match="inside paths.raw_log_dir"):
        load_config(path)
