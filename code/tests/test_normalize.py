"""Phase 80 — normalize stage MVP tests."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from src.config import (
    effective_upload_allowed_suffixes,
    load_config,
    normalize_settings,
)
from src.db.connection import get_connection
from src.normalize.persist import run_normalize
from src.normalize.writers import dead_letter_path, manifest_path
from src.pipeline import STAGE_ORDER


def _base_config(tmp_path: Path, *, normalize: dict | None = None) -> dict:
    data = tmp_path / "data"
    raw = data / "raw"
    uploads = raw / "uploads"
    normalized = raw / "normalized"
    uploads.mkdir(parents=True, exist_ok=True)
    normalized.mkdir(parents=True, exist_ok=True)
    block = {
        "enabled": True,
        "input_dir": None,
        "output_dir": str(normalized),
        "clear_output_on_run": True,
        "converters": ["gunzip", "bunzip2", "unzip", "tar"],
        "on_unsupported": "dead_letter",
        "max_members_per_archive": 500,
        "max_member_bytes": 52_428_800,
        "max_total_output_bytes": 536_870_912,
        "allow_suffixes_passthrough": [
            ".log",
            ".txt",
            ".json",
            ".jsonl",
            ".csv",
            ".ndjson",
        ],
    }
    if normalize:
        block.update(normalize)
    return {
        "paths": {
            "raw_log_dir": str(raw),
            "parsed_dir": str(data / "parsed"),
            "timeseries_dir": str(data / "timeseries"),
            "baseline_dir": str(data / "baselines"),
            "scores_dir": str(data / "scores"),
            "report_dir": str(data / "reports"),
            "analyses_dir": str(data / "analyses"),
            "db_path": str(data / "warehouse.duckdb"),
        },
        "bucketing": {"bucket_seconds": 600},
        "statistical": {"window_buckets": 6, "z_threshold": 4.0},
        "spectral": {
            "window_hours": 72,
            "step_fraction": 0.333,
            "baseline_max_nperseg": 1440,
            "z_threshold": 4.0,
            "cluster_eps": 1.2,
            "cluster_min_samples": 2,
        },
        "ml": {
            "model_type": "isolation_forest",
            "onnx_model_path": None,
            "contamination": 0.02,
            "flagging": "mad_threshold",
            "mad_k": 4.0,
            "min_windows_to_fit": 20,
            "mode": "refit_and_snapshot",
        },
        "correlation": {
            "session_gap_minutes": 30,
            "same_ip_link": True,
            "same_host_link": True,
        },
        "reporting": {
            "template_path": "src/reporting/templates/incident_report.md.j2",
            "use_llm_narrative": False,
            "llm_model": "qwen3-coder:30b",
        },
        "orchestration": {"parallel_backend": "threads", "n_workers": 2},
        "pipeline_ui": {
            "upload_dir": str(uploads),
            "max_upload_bytes": 52_428_800,
            "max_files_per_request": 50,
            "allowed_suffixes": [".log", ".txt", ".json", ".jsonl", ".csv"],
        },
        "normalize": block,
    }


def _write_and_load(tmp_path: Path, config: dict) -> tuple[dict, Path]:
    path = tmp_path / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    loaded = load_config(path)
    get_connection(loaded).close()
    return loaded, path


def test_normalize_stage_order() -> None:
    assert STAGE_ORDER.index("normalize") < STAGE_ORDER.index("ingest")
    assert STAGE_ORDER[0] == "normalize"


def test_normalize_disabled_skip(tmp_path: Path) -> None:
    config = _base_config(tmp_path, normalize={"enabled": False})
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    (uploads / "auth.log").write_text("hello\n", encoding="utf-8")
    loaded, _ = _write_and_load(tmp_path, config)
    original_raw = loaded["paths"]["raw_log_dir"]
    summary = run_normalize(loaded)
    assert summary.skipped_disabled is True
    assert loaded["paths"]["raw_log_dir"] == original_raw
    assert not list(Path(config["normalize"]["output_dir"]).glob("auth.log"))


def test_normalize_gunzip(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    payload = b"Failed password for alice from 10.0.0.1 port 22 ssh2\n"
    gz_path = uploads / "auth.log.gz"
    with gzip.open(gz_path, "wb") as handle:
        handle.write(payload)

    loaded, _ = _write_and_load(tmp_path, config)
    summary = run_normalize(loaded)
    assert summary.files_out == 1
    assert summary.files_converted == 1
    out = Path(config["normalize"]["output_dir"]) / "auth.log"
    assert out.read_bytes() == payload
    rows = [
        json.loads(line)
        for line in manifest_path(Path(config["normalize"]["output_dir"]))
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(rows) == 1
    assert rows[0]["converter"] == "gunzip"
    assert loaded["paths"]["raw_log_dir"] == str(Path(config["normalize"]["output_dir"]))


def test_normalize_passthrough(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    body = '{"event":1}\n{"event":2}\n'
    (uploads / "events.jsonl").write_text(body, encoding="utf-8")
    loaded, _ = _write_and_load(tmp_path, config)
    summary = run_normalize(loaded)
    assert summary.files_passthrough == 1
    out = Path(config["normalize"]["output_dir"]) / "events.jsonl"
    assert out.read_text(encoding="utf-8") == body
    rows = [
        json.loads(line)
        for line in manifest_path(Path(config["normalize"]["output_dir"]))
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert rows[0]["converter"] == "passthrough"


def test_normalize_zip_slip(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    zip_path = uploads / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0::/:/bin/sh\n")
        zf.writestr("ok.log", "safe\n")

    loaded, _ = _write_and_load(tmp_path, config)
    summary = run_normalize(loaded)
    assert summary.dead_lettered == 1
    # No escape outside output_dir
    outside = tmp_path / "etc" / "passwd"
    assert not outside.exists()
    out_root = Path(config["normalize"]["output_dir"]).resolve()
    for path in out_root.rglob("*"):
        if path.is_file() and path.name != "manifest.jsonl":
            path.resolve().relative_to(out_root)
    dead = [
        json.loads(line)
        for line in dead_letter_path(normalize_settings(loaded))
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert dead[0]["reason"] == "zip_slip"


def test_normalize_tar_gz(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    tar_path = uploads / "bundle.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        data = b"line one\nline two\n"
        info = tarfile.TarInfo(name="nested/auth.log")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    loaded, _ = _write_and_load(tmp_path, config)
    summary = run_normalize(loaded)
    assert summary.files_converted == 1
    assert summary.files_out == 1
    out = Path(config["normalize"]["output_dir"]) / "bundle" / "nested" / "auth.log"
    assert out.read_bytes() == b"line one\nline two\n"


def test_normalize_pcap_dead_letter(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    # Fake pcap-like binary without gzip/zip magic
    (uploads / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    loaded, _ = _write_and_load(tmp_path, config)
    summary = run_normalize(loaded)
    assert summary.dead_lettered == 1
    assert summary.files_out == 0
    dead = [
        json.loads(line)
        for line in dead_letter_path(normalize_settings(loaded))
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert dead[0]["reason"] == "unsupported_type"


def test_normalize_policy_b_ingest_dir(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    (uploads / "plain.log").write_text("ok\n", encoding="utf-8")
    loaded, _ = _write_and_load(tmp_path, config)
    out = Path(config["normalize"]["output_dir"])
    run_normalize(loaded)
    assert Path(loaded["paths"]["raw_log_dir"]).resolve() == out.resolve()


def test_upload_archive_suffix_gated(tmp_path: Path) -> None:
    disabled = _base_config(tmp_path, normalize={"enabled": False})
    loaded_off, _ = _write_and_load(tmp_path, disabled)
    off = {s.lower() for s in effective_upload_allowed_suffixes(loaded_off)}
    assert ".gz" not in off

    enabled = _base_config(tmp_path, normalize={"enabled": True})
    # fresh tmp subdir via rewriting output paths already under tmp_path
    loaded_on, _ = _write_and_load(tmp_path, enabled)
    on = {s.lower() for s in effective_upload_allowed_suffixes(loaded_on)}
    assert ".gz" in on
    assert ".zip" in on
    assert ".ndjson" in on


def test_upload_api_rejects_gz_when_normalize_disabled(tmp_path: Path) -> None:
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from src.api.main import create_app
    from src.api.pipeline_jobs import reset_job_store
    from tests.test_api_dashboard import _seed_empty_warehouse, _write_config

    reset_job_store()
    config = _base_config(tmp_path, normalize={"enabled": False})
    _seed_empty_warehouse(config)
    client = TestClient(create_app(_write_config(tmp_path, config)))
    resp = client.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("auth.log.gz", b"\x1f\x8b\x08\x00", "application/gzip"))],
    )
    assert resp.status_code == 400

    config["normalize"]["enabled"] = True
    _write_config(tmp_path, config)
    # recreate app with updated config path
    client2 = TestClient(create_app(tmp_path / "pipeline.yaml"))
    payload = gzip.compress(b"hello\n")
    resp2 = client2.post(
        "/api/v1/pipeline/uploads",
        files=[("files", ("auth.log.gz", payload, "application/gzip"))],
    )
    assert resp2.status_code == 201, resp2.text
    reset_job_store()
