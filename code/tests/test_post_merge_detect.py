"""Phase 90 — post-merge detect gate (one bucket→…→correlate after all shards)."""

from __future__ import annotations

import inspect
import json
import shutil
from pathlib import Path

import pytest
import yaml

from src.config import load_config
from src.db.connection import get_connection
from src.ingestion.sharding.orchestrate import (
    POST_MERGE_STAGES,
    ShardStageStatus,
    ShardedIngestParseResult,
    assert_shards_ready_for_detect,
    corpus_digest_from_shards,
    run_sharded_pipeline,
    run_sharded_post_merge_detect,
    run_sharded_through_parse,
)
from src.ingestion.sharding.split import ShardError, split_log_file
from src.pipeline import main as pipeline_main

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"


def _base_config(tmp_path: Path) -> dict:
    data = tmp_path / "data"
    raw = data / "raw"
    shards = raw / "shards"
    config_dir = tmp_path / "config"
    raw.mkdir(parents=True)
    shards.mkdir(parents=True)
    config_dir.mkdir(parents=True)
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
            "min_windows_to_fit": 5,
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
        "parse": {
            "mode": "train_and_snapshot",
            "start_empty": True,
            "snapshot_id": None,
        },
        "sharding": {
            "enabled": False,
            "target_shard_bytes": 200,
            "target_shard_lines": None,
            "output_dir": str(shards),
            "max_shards": 50,
            "prefer_server_path": True,
            "analysis_window": {"enabled": False, "last_days": 30},
        },
        "_config_dir": str(config_dir),
    }


def _write_and_load(tmp_path: Path, config: dict) -> tuple[dict, Path]:
    config_dir = Path(config.pop("_config_dir"))
    path = config_dir / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    loaded = load_config(path)
    get_connection(loaded).close()
    return loaded, path


def test_gate_blocks_incomplete_shards() -> None:
    result = ShardedIngestParseResult(split_run_id="x", shard_count=2)
    result.shard_statuses = [
        ShardStageStatus(
            shard_index=0,
            shard_path="a",
            shard_sha256="aa",
            ingest_ok=True,
            parse_ok=True,
        ),
        ShardStageStatus(
            shard_index=1,
            shard_path="b",
            shard_sha256="bb",
            ingest_ok=True,
            parse_ok=False,
        ),
    ]
    with pytest.raises(ShardError, match="not ingest_ok/parse_ok"):
        assert_shards_ready_for_detect(result)


def test_post_merge_one_correlate_not_per_shard(tmp_path: Path) -> None:
    config, config_path = _write_and_load(tmp_path, _base_config(tmp_path))
    source = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    shutil.copy(FIXTURE, source)

    result = run_sharded_pipeline(
        config,
        config_path=str(config_path),
        through="report",
        input_path=source,
        split_run_id="post-merge",
    )
    assert result.shard_count >= 2
    assert result.corpus_digest
    assert result.post_merge_ran is True
    assert result.run_dir is not None
    meta = json.loads((result.run_dir / "post_merge.json").read_text(encoding="utf-8"))
    assert meta["corpus_digest"] == result.corpus_digest
    assert meta["post_merge_ran"] is True
    assert "correlate" in meta["post_merge_stages"]

    connection = get_connection(config)
    try:
        # Exactly one correlate attempt for the whole sharded run (success or soft-skip).
        correlate_rows = connection.execute(
            """
            SELECT status, params_json FROM pipeline_runs
            WHERE stage = 'correlate'
            ORDER BY started_at
            """
        ).fetchall()
        assert len(correlate_rows) == 1

        # Bucket also once (not per shard).
        bucket_n = connection.execute(
            "SELECT COUNT(*) FROM pipeline_runs WHERE stage = 'bucket'"
        ).fetchone()[0]
        assert int(bucket_n) == 1

        # Ingest still N times (per shard).
        ingest_n = connection.execute(
            """
            SELECT COUNT(*) FROM pipeline_runs
            WHERE stage = 'ingest' AND status = 'success'
            """
        ).fetchone()[0]
        assert int(ingest_n) == result.shard_count
    finally:
        connection.close()


def test_orchestrator_loop_does_not_call_correlate() -> None:
    """Regression: per-shard correlate must not appear in the ingest/parse loop."""
    source = inspect.getsource(run_sharded_through_parse)
    assert "run_correlate" not in source
    assert "correlate" not in source or "Detectors / correlate are **not**" in source
    # Stronger: POST_MERGE_STAGES is the only place correlate is scheduled.
    assert "correlate" in POST_MERGE_STAGES
    assert POST_MERGE_STAGES.index("bucket") == 0
    assert POST_MERGE_STAGES[-2] == "correlate"
    assert POST_MERGE_STAGES[-1] == "report"


def test_corpus_digest_covers_all_shards(tmp_path: Path) -> None:
    config, _ = _write_and_load(tmp_path, _base_config(tmp_path))
    source = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    shutil.copy(FIXTURE, source)
    split = split_log_file(
        source,
        output_dir=config["sharding"]["output_dir"],
        target_shard_bytes=180,
        run_id="digest",
    )
    digest = corpus_digest_from_shards(list(split.records))
    assert len(digest) == 64
    # Order-independent merkle.
    reversed_recs = list(reversed(split.records))
    assert corpus_digest_from_shards(reversed_recs) == digest


def test_cli_run_sharded_through_report(tmp_path: Path) -> None:
    config, config_path = _write_and_load(tmp_path, _base_config(tmp_path))
    source = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    shutil.copy(FIXTURE, source)
    code = pipeline_main(
        [
            "run-sharded",
            "--config",
            str(config_path),
            "--through",
            "report",
            "--input",
            str(source),
            "--run-id",
            "cli-report",
        ]
    )
    # Soft-skips on short fixture may yield 0; hard failures yield 1.
    assert code in (0, 1)
    connection = get_connection(config)
    try:
        correlate_n = connection.execute(
            "SELECT COUNT(*) FROM pipeline_runs WHERE stage = 'correlate'"
        ).fetchone()[0]
        assert int(correlate_n) == 1
    finally:
        connection.close()


def test_post_merge_refuses_without_parse(tmp_path: Path) -> None:
    config, config_path = _write_and_load(tmp_path, _base_config(tmp_path))
    empty = ShardedIngestParseResult(split_run_id="none", shard_count=2)
    with pytest.raises(ShardError, match="refused"):
        run_sharded_post_merge_detect(
            config, empty, config_path=str(config_path)
        )
