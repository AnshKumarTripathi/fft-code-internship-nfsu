"""Tests for the pipeline CLI shell."""

from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.config import load_config

CODE_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"
SPECTRAL_SEED_ENTITIES = ["entity_syn_a", "entity_syn_b", "entity_syn_c"]
LONG_AUTH_USERS = ("alice", "bob", "carol")


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "src.pipeline", *args],
        cwd=cwd or CODE_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _seed_spectral_history(config_path: Path) -> None:
    from tests.fixtures.seed_spectral import seed_entity_bucket_series

    config = load_config(config_path)
    seed_entity_bucket_series(config, SPECTRAL_SEED_ENTITIES)


def _write_long_auth_fixture(raw_dir: Path, *, n_buckets: int = 5000) -> None:
    """Auth-style log spanning enough buckets with daily periodic event rates."""
    import math

    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    period = 24 * 3600 // 600
    lines: list[str] = []
    for bucket_idx in range(n_buckets):
        bucket_start = start + timedelta(seconds=600 * bucket_idx)
        weight = 0.5 + 0.5 * math.sin(2 * math.pi * bucket_idx / period)
        n_events = max(1, int(round(weight * 3)))
        for event_idx in range(n_events):
            ts_str = (bucket_start + timedelta(seconds=event_idx)).strftime(
                "%b %d %H:%M:%S"
            )
            for user in LONG_AUTH_USERS:
                lines.append(
                    f"{ts_str} hostname sshd[{1000 + bucket_idx}]: "
                    f"Accepted password for {user} from 10.0.0.{event_idx + 1} "
                    f"port {22000 + bucket_idx + event_idx} ssh2"
                )
    (raw_dir / "auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_help_lists_all_subcommands() -> None:
    result = _run("--help")
    assert result.returncode == 0
    for name in (
        "ingest",
        "parse",
        "bucket",
        "detect-statistical",
        "detect-spectral",
        "detect-ml",
        "detect-changepoint",
        "cluster",
        "correlate",
        "report",
        "run-all",
        "evaluate",
    ):
        assert name in result.stdout


def test_parse_stage_runs_after_ingest(tmp_path: Path) -> None:
    data = tmp_path / "data"
    raw = data / "raw"
    raw.mkdir(parents=True)
    shutil.copy(FIXTURE, raw / "auth.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(CODE_ROOT / "config" / "drain3.ini", config_dir / "drain3.ini")
    config_path = config_dir / "pipeline.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  raw_log_dir: {raw.as_posix()}/",
                f"  parsed_dir: {(data / 'parsed').as_posix()}/",
                f"  timeseries_dir: {(data / 'timeseries').as_posix()}/",
                f"  baseline_dir: {(data / 'baselines').as_posix()}/",
                f"  scores_dir: {(data / 'scores').as_posix()}/",
                f"  report_dir: {(data / 'reports').as_posix()}/",
                f"  db_path: {(data / 'warehouse.duckdb').as_posix()}",
                "bucketing:",
                "  bucket_seconds: 600",
                "statistical:",
                "  window_buckets: 6",
                "  z_threshold: 4.0",
                "spectral:",
                "  window_hours: 72",
                "  step_fraction: 0.333",
                "  baseline_max_nperseg: 1440",
                "  z_threshold: 4.0",
                "  cluster_eps: 1.2",
                "  cluster_min_samples: 2",
                "ml:",
                "  model_type: isolation_forest",
                "  onnx_model_path: null",
                "  contamination: 0.02",
                "correlation:",
                "  session_gap_minutes: 30",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: dask",
                "  n_workers: 8",
                "",
            ]
        ),
        encoding="utf-8",
    )

    ingest = _run("ingest", "--config", str(config_path), cwd=CODE_ROOT)
    assert ingest.returncode == 0, ingest.stderr

    parse = _run("parse", "--config", str(config_path), cwd=CODE_ROOT)
    assert parse.returncode == 0, parse.stderr
    assert "parse summary" in parse.stdout

    bucket = _run("bucket", "--config", str(config_path), cwd=CODE_ROOT)
    assert bucket.returncode == 0, bucket.stderr
    assert "bucket summary" in bucket.stdout

    detect = _run("detect-statistical", "--config", str(config_path), cwd=CODE_ROOT)
    assert detect.returncode == 0, detect.stderr
    assert "detect-statistical summary" in detect.stdout

    _seed_spectral_history(config_path)

    spectral = _run("detect-spectral", "--config", str(config_path), cwd=CODE_ROOT)
    assert spectral.returncode == 0, spectral.stderr
    assert "detect-spectral summary" in spectral.stdout

    cluster = _run("cluster", "--config", str(config_path), cwd=CODE_ROOT)
    assert cluster.returncode == 0, cluster.stderr
    assert "cluster summary" in cluster.stdout

    detect_ml = _run("detect-ml", "--config", str(config_path), cwd=CODE_ROOT)
    assert detect_ml.returncode == 0, detect_ml.stderr
    assert "detect-ml summary" in detect_ml.stdout


def test_detect_ml_onnx_misconfig_exits_nonzero(tmp_path: Path) -> None:
    data = tmp_path / "data"
    raw = data / "raw"
    raw.mkdir(parents=True)
    shutil.copy(FIXTURE, raw / "auth.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(CODE_ROOT / "config" / "drain3.ini", config_dir / "drain3.ini")
    config_path = config_dir / "pipeline.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  raw_log_dir: {raw.as_posix()}/",
                f"  parsed_dir: {(data / 'parsed').as_posix()}/",
                f"  timeseries_dir: {(data / 'timeseries').as_posix()}/",
                f"  baseline_dir: {(data / 'baselines').as_posix()}/",
                f"  scores_dir: {(data / 'scores').as_posix()}/",
                f"  report_dir: {(data / 'reports').as_posix()}/",
                f"  db_path: {(data / 'warehouse.duckdb').as_posix()}",
                "bucketing:",
                "  bucket_seconds: 600",
                "statistical:",
                "  window_buckets: 6",
                "  z_threshold: 4.0",
                "spectral:",
                "  window_hours: 72",
                "  step_fraction: 0.333",
                "  baseline_max_nperseg: 1440",
                "  z_threshold: 4.0",
                "  cluster_eps: 1.2",
                "  cluster_min_samples: 2",
                "ml:",
                "  model_type: onnx",
                "  onnx_model_path: null",
                "  contamination: 0.02",
                "correlation:",
                "  session_gap_minutes: 30",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: dask",
                "  n_workers: 8",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert _run("ingest", "--config", str(config_path), cwd=CODE_ROOT).returncode == 0
    assert _run("parse", "--config", str(config_path), cwd=CODE_ROOT).returncode == 0

    result = _run("detect-ml", "--config", str(config_path), cwd=CODE_ROOT)
    assert result.returncode == 1
    assert "onnx" in result.stderr.lower()


def test_report_cli_nothing_to_report_exits_zero(tmp_path: Path) -> None:
    data = tmp_path / "data"
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "pipeline.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  raw_log_dir: {(data / 'raw').as_posix()}/",
                f"  parsed_dir: {(data / 'parsed').as_posix()}/",
                f"  timeseries_dir: {(data / 'timeseries').as_posix()}/",
                f"  baseline_dir: {(data / 'baselines').as_posix()}/",
                f"  scores_dir: {(data / 'scores').as_posix()}/",
                f"  report_dir: {(data / 'reports').as_posix()}/",
                f"  db_path: {(data / 'warehouse.duckdb').as_posix()}",
                "bucketing:",
                "  bucket_seconds: 600",
                "statistical:",
                "  window_buckets: 6",
                "  z_threshold: 4.0",
                "spectral:",
                "  window_hours: 72",
                "  step_fraction: 0.333",
                "  baseline_max_nperseg: 1440",
                "  z_threshold: 4.0",
                "  cluster_eps: 1.2",
                "  cluster_min_samples: 2",
                "ml:",
                "  model_type: isolation_forest",
                "  onnx_model_path: null",
                "  contamination: 0.02",
                "correlation:",
                "  session_gap_minutes: 30",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: dask",
                "  n_workers: 8",
                "",
            ]
        ),
        encoding="utf-8",
    )
    result = _run("report", "--config", str(config_path), cwd=CODE_ROOT)
    assert result.returncode == 0
    assert "nothing to report" in result.stdout


def test_report_cli_writes_file(tmp_path: Path) -> None:
    data = tmp_path / "data"
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "pipeline.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  raw_log_dir: {(data / 'raw').as_posix()}/",
                f"  parsed_dir: {(data / 'parsed').as_posix()}/",
                f"  timeseries_dir: {(data / 'timeseries').as_posix()}/",
                f"  baseline_dir: {(data / 'baselines').as_posix()}/",
                f"  scores_dir: {(data / 'scores').as_posix()}/",
                f"  report_dir: {(data / 'reports').as_posix()}/",
                f"  db_path: {(data / 'warehouse.duckdb').as_posix()}",
                "bucketing:",
                "  bucket_seconds: 600",
                "statistical:",
                "  window_buckets: 6",
                "  z_threshold: 4.0",
                "spectral:",
                "  window_hours: 72",
                "  step_fraction: 0.333",
                "  baseline_max_nperseg: 1440",
                "  z_threshold: 4.0",
                "  cluster_eps: 1.2",
                "  cluster_min_samples: 2",
                "ml:",
                "  model_type: isolation_forest",
                "  onnx_model_path: null",
                "  contamination: 0.02",
                "correlation:",
                "  session_gap_minutes: 30",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: dask",
                "  n_workers: 8",
                "",
            ]
        ),
        encoding="utf-8",
    )

    from src.config import load_config
    from src.db.connection import get_connection

    config = load_config(str(config_path))
    connection = get_connection(config)
    try:
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
            VALUES ('anom-cli', 'alice', ?, ?, 'ml', 0.9, '{}'::JSON)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity, summary_text, contributing_anomaly_ids)
            VALUES ('inc-cli', 'alice', ?, ?, 'low', 'cli stub', ?)
            """,
            [start, end, ["anom-cli"]],
        )
    finally:
        connection.close()

    result = _run("report", "--config", str(config_path), cwd=CODE_ROOT)
    assert result.returncode == 0, result.stderr
    assert "report summary" in result.stdout
    reports = list((data / "reports").glob("incident_*.md"))
    assert reports
    assert "inc-cli" in reports[0].read_text(encoding="utf-8")


def test_correlate_cli_with_seeded_scores(tmp_path: Path) -> None:
    data = tmp_path / "data"
    raw = data / "raw"
    raw.mkdir(parents=True)
    shutil.copy(FIXTURE, raw / "auth.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(CODE_ROOT / "config" / "drain3.ini", config_dir / "drain3.ini")
    config_path = config_dir / "pipeline.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  raw_log_dir: {raw.as_posix()}/",
                f"  parsed_dir: {(data / 'parsed').as_posix()}/",
                f"  timeseries_dir: {(data / 'timeseries').as_posix()}/",
                f"  baseline_dir: {(data / 'baselines').as_posix()}/",
                f"  scores_dir: {(data / 'scores').as_posix()}/",
                f"  report_dir: {(data / 'reports').as_posix()}/",
                f"  db_path: {(data / 'warehouse.duckdb').as_posix()}",
                "bucketing:",
                "  bucket_seconds: 600",
                "statistical:",
                "  window_buckets: 6",
                "  z_threshold: 4.0",
                "spectral:",
                "  window_hours: 72",
                "  step_fraction: 0.333",
                "  baseline_max_nperseg: 1440",
                "  z_threshold: 4.0",
                "  cluster_eps: 1.2",
                "  cluster_min_samples: 2",
                "ml:",
                "  model_type: isolation_forest",
                "  onnx_model_path: null",
                "  contamination: 0.02",
                "correlation:",
                "  session_gap_minutes: 30",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: dask",
                "  n_workers: 8",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert _run("ingest", "--config", str(config_path), cwd=CODE_ROOT).returncode == 0
    assert _run("parse", "--config", str(config_path), cwd=CODE_ROOT).returncode == 0

    # Seed a flagged statistical window for an entity that exists after parse.
    from src.config import load_config
    from src.db.connection import get_connection

    config = load_config(str(config_path))
    connection = get_connection(config)
    try:
        entity = connection.execute(
            "SELECT entity_id FROM parsed_events LIMIT 1"
        ).fetchone()
        assert entity is not None
        entity_id = entity[0]
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES (?, ?, ?, 5.0, TRUE)
            """,
            [entity_id, start, end],
        )
    finally:
        connection.close()

    result = _run("correlate", "--config", str(config_path), cwd=CODE_ROOT)
    assert result.returncode == 0, result.stderr
    assert "correlate summary" in result.stdout


def test_run_all_runs_through_correlate_or_skips_softly(tmp_path: Path) -> None:
    # Use an isolated config so run-all does not touch the repo warehouse.
    data = tmp_path / "data"
    raw = data / "raw"
    raw.mkdir(parents=True)
    _write_long_auth_fixture(raw)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(CODE_ROOT / "config" / "drain3.ini", config_dir / "drain3.ini")
    config_path = config_dir / "pipeline.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  raw_log_dir: {raw.as_posix()}/",
                f"  parsed_dir: {(data / 'parsed').as_posix()}/",
                f"  timeseries_dir: {(data / 'timeseries').as_posix()}/",
                f"  baseline_dir: {(data / 'baselines').as_posix()}/",
                f"  scores_dir: {(data / 'scores').as_posix()}/",
                f"  report_dir: {(data / 'reports').as_posix()}/",
                f"  db_path: {(data / 'warehouse.duckdb').as_posix()}",
                "bucketing:",
                "  bucket_seconds: 600",
                "statistical:",
                "  window_buckets: 6",
                "  z_threshold: 4.0",
                "spectral:",
                "  window_hours: 72",
                "  step_fraction: 0.333",
                "  baseline_max_nperseg: 1440",
                "  z_threshold: 4.0",
                "  cluster_eps: 1.2",
                "  cluster_min_samples: 2",
                "ml:",
                "  model_type: isolation_forest",
                "  onnx_model_path: null",
                "  contamination: 0.02",
                "correlation:",
                "  session_gap_minutes: 30",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: dask",
                "  n_workers: 8",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = _run("run-all", "--config", str(config_path), cwd=CODE_ROOT)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "detect-ml" in result.stdout
    assert "detect-changepoint" in result.stdout
    assert "failed:  (none)" in result.stdout
    # correlate/report either ran or soft-skipped
    assert "correlate" in result.stdout
    assert "report" in result.stdout
