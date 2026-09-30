"""R4 sealed run manifest (git / yaml / drain3.ini / packages)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.db.connection import get_connection, record_run_start
from src.db.run_manifest import build_run_manifest, package_versions


def test_manifest_hashes_pipeline_yaml_bytes(tmp_path: Path) -> None:
    yaml_path = tmp_path / "pipeline.yaml"
    payload = b"bucketing:\n  bucket_seconds: 600\n"
    yaml_path.write_bytes(payload)
    ini_path = tmp_path / "drain3.ini"
    ini_path.write_bytes(b"[SNAPSHOT]\nserialize=true\n")

    manifest = build_run_manifest(yaml_path)
    assert manifest["pipeline_yaml_sha256"] == hashlib.sha256(payload).hexdigest()
    assert manifest["drain3_ini_sha256"] == hashlib.sha256(ini_path.read_bytes()).hexdigest()
    assert "git_commit" in manifest
    versions = manifest["package_versions"]
    assert "numpy" in versions
    assert "scipy" in versions
    assert "sklearn" in versions
    assert "drain3" in versions


def test_manifest_null_yaml_when_path_missing() -> None:
    manifest = build_run_manifest("not-a-real-config.yaml")
    assert manifest["pipeline_yaml_sha256"] is None


def test_package_versions_include_numpy() -> None:
    versions = package_versions()
    assert versions["numpy"]


def test_record_run_start_embeds_manifest(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    config = {
        "paths": {
            "raw_log_dir": str(data_root / "raw"),
            "parsed_dir": str(data_root / "parsed"),
            "timeseries_dir": str(data_root / "timeseries"),
            "baseline_dir": str(data_root / "baselines"),
            "scores_dir": str(data_root / "scores"),
            "report_dir": str(data_root / "reports"),
            "db_path": str(data_root / "warehouse.duckdb"),
        }
    }
    yaml_path = tmp_path / "pipeline.yaml"
    yaml_path.write_bytes(b"x: 1\n")
    connection = get_connection(config)
    try:
        params = {"config_path": str(yaml_path)}
        run_id = record_run_start(connection, stage="bucket", params=params)
        row = connection.execute(
            "SELECT params_json FROM pipeline_runs WHERE run_id = ?",
            [run_id],
        ).fetchone()
        payload = row[0]
        if isinstance(payload, str):
            payload = json.loads(payload)
        assert "manifest" in payload
        assert payload["manifest"]["pipeline_yaml_sha256"] == hashlib.sha256(b"x: 1\n").hexdigest()
        assert params["manifest"]["pipeline_yaml_sha256"] == payload["manifest"][
            "pipeline_yaml_sha256"
        ]
        assert payload["manifest"]["parser_snapshot_id"] is None
        assert payload["manifest"]["model_snapshot_id"] is None
        assert payload["manifest"]["onnx_model_hash"] is None
        assert payload["manifest"]["cluster_run_id"] is None
    finally:
        connection.close()
