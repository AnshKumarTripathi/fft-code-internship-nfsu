"""POST /api/v1/pipeline/lab-reset — wipe regenerable lab outputs."""

from __future__ import annotations

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.lab_reset import reset_lab_data  # noqa: E402
from src.api.main import create_app  # noqa: E402
from src.api.pipeline_jobs import get_job_store, reset_job_store  # noqa: E402
from src.api.pipeline_uploads import upload_dir_from_config  # noqa: E402
from src.config import ensure_data_directories  # noqa: E402
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


def _prepared_config(tmp_path: Path) -> dict:
    config = _full_config(tmp_path)
    config["paths"]["analyses_dir"] = str(tmp_path / "data" / "analyses")
    ensure_data_directories(config)
    _seed_empty_warehouse(config)
    return config


def _client(tmp_path: Path) -> tuple[TestClient, dict]:
    config = _prepared_config(tmp_path)
    return TestClient(create_app(_write_config(tmp_path, config))), config


def test_lab_reset_requires_confirm(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    response = client.post(
        "/api/v1/pipeline/lab-reset",
        json={"confirm": "nope", "clear_uploads": True},
    )
    assert response.status_code == 422


def test_lab_reset_clears_warehouse_and_outputs(tmp_path: Path) -> None:
    client, config = _client(tmp_path)
    db_path = Path(config["paths"]["db_path"])
    reports = Path(config["paths"]["report_dir"])
    (reports / "incident_demo.md").write_text("x", encoding="utf-8")
    analyses = Path(config["paths"]["analyses_dir"])
    snap = analyses / "a1"
    snap.mkdir(parents=True, exist_ok=True)
    (snap / "triage.json").write_text("{}", encoding="utf-8")
    upload_dir = upload_dir_from_config(config)
    (upload_dir / "staged.log").write_text("line\n", encoding="utf-8")

    assert db_path.is_file()
    response = client.post(
        "/api/v1/pipeline/lab-reset",
        json={
            "confirm": "CLEAR",
            "clear_uploads": True,
            "clear_raw_non_upload": False,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert db_path.is_file(), "empty warehouse should be recreated after clear"
    assert not (reports / "incident_demo.md").exists()
    assert not (snap / "triage.json").exists()
    assert not (upload_dir / "staged.log").exists()
    assert get_job_store().latest() is None


def test_lab_reset_blocked_while_job_active(tmp_path: Path, monkeypatch) -> None:
    client, config = _client(tmp_path)

    class _FakeJob:
        status = "running"
        job_id = "j1"

    monkeypatch.setattr(
        get_job_store(),
        "latest",
        lambda: _FakeJob(),
    )
    response = client.post(
        "/api/v1/pipeline/lab-reset",
        json={"confirm": "CLEAR"},
    )
    assert response.status_code == 409
    assert Path(config["paths"]["db_path"]).is_file()


def test_reset_lab_data_keeps_uploads_when_requested(tmp_path: Path) -> None:
    config = _prepared_config(tmp_path)
    upload_dir = upload_dir_from_config(config)
    keep = upload_dir / "keep.log"
    keep.write_text("x\n", encoding="utf-8")

    result = reset_lab_data(config, clear_uploads=False, clear_raw_non_upload=False)
    assert result["ok"] is True
    assert keep.is_file()
