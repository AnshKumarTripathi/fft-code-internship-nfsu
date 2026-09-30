"""R4 ingest source-file hashes, staging Merkle, optional evidence line hash."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.file_hash import hash_file_bytes
from src.ingestion.loaders import hash_raw_line, read_log_files
from src.ingestion.persist import ingest_staging_dir, run_ingest

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"


def _temp_config(tmp_path: Path, *, evidence_line_hash: bool = False) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "auth.log").write_bytes(FIXTURE.read_bytes())
    return {
        "paths": {
            "raw_log_dir": str(raw),
            "parsed_dir": str(data_root / "parsed"),
            "timeseries_dir": str(data_root / "timeseries"),
            "baseline_dir": str(data_root / "baselines"),
            "scores_dir": str(data_root / "scores"),
            "report_dir": str(data_root / "reports"),
            "db_path": str(data_root / "warehouse.duckdb"),
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
        "orchestration": {"parallel_backend": "dask", "n_workers": 8},
        "ingestion": {
            "dedup_backend": "memory",
            "dedup_memory_max_hashes": 2000000,
            "syslog_year_policy": "carry",
            "enabled_sources": [],
            "evidence_line_hash": evidence_line_hash,
        },
    }


def _params(row: object) -> dict:
    payload = row
    if isinstance(payload, str):
        return json.loads(payload)
    assert isinstance(payload, dict)
    return payload


def test_ingest_run_records_file_set_and_config_hash(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    yaml_path = tmp_path / "pipeline.yaml"
    yaml_bytes = b"ingestion:\n  evidence_line_hash: false\n"
    yaml_path.write_bytes(yaml_bytes)
    raw = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    expected_file = hashlib.sha256(raw.read_bytes()).hexdigest()
    expected_yaml = hashlib.sha256(yaml_bytes).hexdigest()

    summary = run_ingest(config, config_path=str(yaml_path))
    assert summary.staging_merkle_sha256
    assert summary.evidence_line_hash is False

    connection = get_connection(config)
    try:
        files = connection.execute(
            """
            SELECT source_path, sha256, size_bytes
            FROM ingest_source_files
            """
        ).fetchall()
        assert len(files) == 1
        assert files[0][1] == expected_file
        assert int(files[0][2]) == raw.stat().st_size

        run_row = connection.execute(
            """
            SELECT run_id, status, params_json
            FROM pipeline_runs
            WHERE stage = 'ingest'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
        assert run_row[1] == "success"
        params = _params(run_row[2])
        assert params["manifest"]["pipeline_yaml_sha256"] == expected_yaml
        assert params["staging"]["merkle_sha256"] == summary.staging_merkle_sha256
        assert params["staging"]["part_count"] == summary.staging_parts

        owned = connection.execute(
            """
            SELECT COUNT(*) FROM ingest_source_files WHERE run_id = ?
            """,
            [run_row[0]],
        ).fetchone()[0]
        assert int(owned) == 1
    finally:
        connection.close()


def test_ingest_file_hash_changes_when_raw_byte_mutated(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    raw = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    before = hash_file_bytes(raw).sha256
    run_ingest(config, config_path="test")
    mutated = raw.read_bytes() + b"\n"
    raw.write_bytes(mutated)
    assert hash_file_bytes(raw).sha256 != before
    run_ingest(config, config_path="test")

    connection = get_connection(config)
    try:
        hashes = [
            row[0]
            for row in connection.execute(
                "SELECT sha256 FROM ingest_source_files ORDER BY run_id"
            ).fetchall()
        ]
        assert len(set(hashes)) == 2
    finally:
        connection.close()


def test_default_ingest_does_not_write_evidence_hash(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    run_ingest(config, config_path="test")
    staging = ingest_staging_dir(config)
    import pandas as pd

    frame = pd.concat(
        [pd.read_parquet(path) for path in staging.glob("*.parquet")],
        ignore_index=True,
    )
    if "evidence_hash" in frame.columns:
        assert frame["evidence_hash"].isna().all()


def test_evidence_line_hash_uses_raw_bytes_not_utf8_replace(tmp_path: Path) -> None:
    config = _temp_config(tmp_path, evidence_line_hash=True)
    line_bytes = b"Jan 15 10:00:01 host sshd[1]: Failed password for caf\xe9 from 1.2.3.4 port 1 ssh2"
    (Path(config["paths"]["raw_log_dir"]) / "auth.log").write_bytes(line_bytes + b"\n")

    lines = list(read_log_files(config, evidence_line_hash=True))
    assert len(lines) == 1
    assert lines[0].evidence_hash == hashlib.sha256(line_bytes).hexdigest()
    decoded = line_bytes.decode("latin-1")
    assert lines[0].content_hash == hash_raw_line(decoded)
    assert lines[0].evidence_hash != lines[0].content_hash

    summary = run_ingest(config, config_path="test")
    assert summary.evidence_line_hash is True
    assert summary.lines_kept == 1


def test_evidence_flag_does_not_change_policy_a_dedup(tmp_path: Path) -> None:
    config = _temp_config(tmp_path, evidence_line_hash=True)
    summary = run_ingest(config, config_path="test")
    off = _temp_config(tmp_path / "off", evidence_line_hash=False)
    off_summary = run_ingest(off, config_path="test")
    assert summary.lines_read == off_summary.lines_read
    assert summary.lines_kept == off_summary.lines_kept
    assert summary.lines_deduped == off_summary.lines_deduped


def test_utf8_content_hash_matches_with_or_without_evidence_flag(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    text = "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2\n"
    (raw_dir / "auth.log").write_text(text, encoding="utf-8")
    config = {"paths": {"raw_log_dir": str(raw_dir)}}
    without = list(read_log_files(config, evidence_line_hash=False))
    with_flag = list(read_log_files(config, evidence_line_hash=True))
    assert without[0].content_hash == with_flag[0].content_hash
    assert with_flag[0].evidence_hash == hashlib.sha256(
        text.rstrip("\n").encode("utf-8")
    ).hexdigest()
    assert without[0].evidence_hash is None
