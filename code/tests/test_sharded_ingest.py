"""Phase 89 — sharded ingest/parse into one warehouse."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from src.config import load_config
from src.db.connection import get_connection
from src.ingestion.sharding.orchestrate import run_sharded_through_parse
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


def test_sharded_same_entity_across_shards(tmp_path: Path) -> None:
    config, config_path = _write_and_load(tmp_path, _base_config(tmp_path))
    source = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    shutil.copy(FIXTURE, source)

    split = split_log_file(
        source,
        output_dir=config["sharding"]["output_dir"],
        target_shard_bytes=180,
        max_shards=20,
        run_id="entity-check",
    )
    assert split.shard_count >= 2

    result = run_sharded_through_parse(
        config,
        config_path=str(config_path),
        split_run_id="entity-check",
    )
    assert result.shard_count >= 2
    assert result.parser_trained_snapshot_id
    assert "alice" in result.entities_seen

    connection = get_connection(config)
    try:
        alice_count = connection.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE entity_id = ?",
            ["alice"],
        ).fetchone()[0]
        assert int(alice_count) >= 2

        # Shard metadata recorded on ingest/parse runs.
        rows = connection.execute(
            """
            SELECT params_json FROM pipeline_runs
            WHERE stage IN ('ingest', 'parse') AND status = 'success'
            """
        ).fetchall()
        shard_indexes: set[int] = set()
        for (payload,) in rows:
            if isinstance(payload, str):
                payload = json.loads(payload)
            if payload.get("sharded"):
                shard_indexes.add(int(payload["shard_index"]))
        assert len(shard_indexes) >= 2

        # Later parse runs must reuse_snapshot (not retrain).
        parse_modes = []
        for (payload,) in rows:
            if isinstance(payload, str):
                payload = json.loads(payload)
            if payload.get("sharded") and payload.get("parse_mode"):
                parse_modes.append(
                    (int(payload["shard_index"]), payload["parse_mode"])
                )
        parse_modes.sort()
        assert parse_modes[0][1] == "train_and_snapshot"
        assert all(mode == "reuse_snapshot" for _, mode in parse_modes[1:])
    finally:
        connection.close()


def test_reuse_snapshot_without_id_rejected_at_config(tmp_path: Path) -> None:
    """Pre-frozen whole-run reuse still requires snapshot_id (config gate)."""
    base = _base_config(tmp_path)
    base["parse"] = {
        "mode": "reuse_snapshot",
        "snapshot_id": None,
        "start_empty": False,
    }
    config_dir = Path(base.pop("_config_dir"))
    path = config_dir / "pipeline.yaml"
    path.write_text(yaml.safe_dump(base), encoding="utf-8")
    with pytest.raises(Exception, match="snapshot_id"):
        load_config(path)


def test_cli_run_sharded_through_parse(tmp_path: Path) -> None:
    config, config_path = _write_and_load(tmp_path, _base_config(tmp_path))
    source = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    shutil.copy(FIXTURE, source)
    code = pipeline_main(
        [
            "run-sharded",
            "--config",
            str(config_path),
            "--through",
            "parse",
            "--input",
            str(source),
            "--run-id",
            "cli-sharded",
        ]
    )
    assert code == 0
    connection = get_connection(config)
    try:
        events = connection.execute("SELECT COUNT(*) FROM parsed_events").fetchone()[0]
        entities = connection.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
        assert int(events) > 0
        assert int(entities) > 0
    finally:
        connection.close()
