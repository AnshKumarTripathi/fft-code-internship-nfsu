"""Phase 41: Jinja off by default; JSON API and health stay on."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.api.main import create_app
from src.api.routes.legacy_stub import LEGACY_HTML_OFF_DETAIL

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_api_dashboard import _full_config, _seed_incident_warehouse  # noqa: E402


def _write_config(tmp_path: Path, config: dict) -> Path:
    path = tmp_path / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def _client(tmp_path: Path, *, serve_legacy_html: bool) -> TestClient:
    config = _full_config(tmp_path)
    config["dashboard"] = {"serve_legacy_html": serve_legacy_html}
    _seed_incident_warehouse(config)
    return TestClient(create_app(_write_config(tmp_path, config)))


def test_default_yaml_disables_jinja_home() -> None:
    from src.config import dashboard_settings, load_config

    repo_config = Path(__file__).resolve().parents[1] / "config" / "pipeline.yaml"
    settings = dashboard_settings(load_config(repo_config))
    assert settings["serve_legacy_html"] is False


def test_flag_false_home_is_not_jinja_table(tmp_path: Path) -> None:
    client = _client(tmp_path, serve_legacy_html=False)
    response = client.get("/")
    assert response.status_code == 404
    body = response.json()
    assert "3000" in body["detail"]
    assert LEGACY_HTML_OFF_DETAIL in body["detail"]
    assert "Showing" not in response.text
    assert "kpi-strip" not in response.text
    assert "incidents_list" not in response.text


def test_flag_false_json_and_health_stay_on(tmp_path: Path) -> None:
    client = _client(tmp_path, serve_legacy_html=False)
    incidents = client.get("/api/v1/incidents")
    assert incidents.status_code == 200
    assert incidents.json()["total"] >= 1
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"


def test_flag_true_still_serves_jinja(tmp_path: Path) -> None:
    client = _client(tmp_path, serve_legacy_html=True)
    response = client.get("/")
    assert response.status_code == 200
    assert "inc-1" in response.text
    assert "Showing" in response.text or "Incidents" in response.text
