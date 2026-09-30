"""Phase 88 — line-safe shard splitter tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from src.config import ConfigError, load_config, sharding_settings
from src.ingestion.file_hash import hash_file_bytes
from src.ingestion.sharding.manifest import read_manifest
from src.ingestion.sharding.split import ShardError, split_log_file
from src.pipeline import main as pipeline_main


def _base_config(tmp_path: Path, *, sharding: dict | None = None) -> dict:
    data = tmp_path / "data"
    raw = data / "raw"
    shards = raw / "shards"
    raw.mkdir(parents=True, exist_ok=True)
    shards.mkdir(parents=True, exist_ok=True)
    block = {
        "enabled": False,
        "target_shard_bytes": 64,
        "target_shard_lines": None,
        "output_dir": str(shards),
        "max_shards": 500,
        "prefer_server_path": True,
        "analysis_window": {"enabled": False, "last_days": 30},
    }
    if sharding:
        block.update(sharding)
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
        "sharding": block,
    }


def _write_and_load(tmp_path: Path, config: dict) -> tuple[dict, Path]:
    path = tmp_path / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return load_config(path), path


def _make_fixture(path: Path, *, lines: int = 200, line_bytes: int = 40) -> bytes:
    """Build a ~N×line_bytes text body with known newlines (≈10 KB default)."""
    chunks: list[bytes] = []
    for i in range(lines):
        payload = f"line-{i:05d}-".encode("ascii")
        pad = b"x" * max(0, line_bytes - len(payload) - 1)
        chunks.append(payload + pad + b"\n")
    body = b"".join(chunks)
    path.write_bytes(body)
    return body


def test_line_safe_split_concat_equals_source(tmp_path: Path) -> None:
    source = tmp_path / "corpus.log"
    body = _make_fixture(source, lines=250, line_bytes=48)
    out = tmp_path / "shards"
    result = split_log_file(
        source,
        output_dir=out,
        target_shard_bytes=200,
        max_shards=50,
        run_id="concat-check",
    )
    assert result.shard_count >= 2
    rebuilt = b"".join(
        Path(record.shard_path).read_bytes() for record in result.records
    )
    assert rebuilt == body
    assert hashlib.sha256(rebuilt).hexdigest() == result.source_sha256
    for record in result.records:
        shard_bytes = Path(record.shard_path).read_bytes()
        slice_bytes = body[record.byte_start : record.byte_end]
        assert slice_bytes == shard_bytes
        if record.shard_index < result.shard_count - 1:
            assert shard_bytes.endswith(b"\n")


def test_never_splits_mid_line(tmp_path: Path) -> None:
    source = tmp_path / "long_lines.log"
    # Soft target smaller than one line → still keep whole lines intact.
    lines = [b"AAAA" * 20 + b"\n", b"BBBB" * 20 + b"\n", b"CCCC" * 20 + b"\n"]
    body = b"".join(lines)
    source.write_bytes(body)
    result = split_log_file(
        source,
        output_dir=tmp_path / "shards",
        target_shard_bytes=10,
        max_shards=10,
        run_id="midline",
    )
    assert result.shard_count == 3
    for record, expected in zip(result.records, lines, strict=True):
        assert Path(record.shard_path).read_bytes() == expected


def test_empty_input_rejected(tmp_path: Path) -> None:
    source = tmp_path / "empty.log"
    source.write_bytes(b"")
    with pytest.raises(ShardError, match="empty"):
        split_log_file(
            source,
            output_dir=tmp_path / "shards",
            target_shard_bytes=100,
            run_id="empty",
        )


def test_max_shards_enforced(tmp_path: Path) -> None:
    source = tmp_path / "many.log"
    _make_fixture(source, lines=40, line_bytes=20)
    with pytest.raises(ShardError, match="max_shards"):
        split_log_file(
            source,
            output_dir=tmp_path / "shards",
            target_shard_bytes=20,
            max_shards=2,
            run_id="cap",
        )


def test_manifest_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "corp.log"
    body = _make_fixture(source, lines=30, line_bytes=32)
    result = split_log_file(
        source,
        output_dir=tmp_path / "shards",
        target_shard_lines=10,
        target_shard_bytes=None,
        max_shards=10,
        run_id="manifest",
    )
    loaded = read_manifest(result.manifest_path)
    assert len(loaded) == result.shard_count
    assert loaded[0].source_sha256 == hash_file_bytes(source).sha256
    assert loaded[0].source_size_bytes == len(body)
    for record in loaded:
        assert record.byte_end > record.byte_start
        assert record.line_end >= record.line_start
        assert body[record.byte_start : record.byte_end] == Path(
            record.shard_path
        ).read_bytes()


def test_sharding_config_defaults_disabled(tmp_path: Path) -> None:
    config, _ = _write_and_load(tmp_path, _base_config(tmp_path))
    settings = sharding_settings(config)
    assert settings["enabled"] is False
    assert settings["max_shards"] == 500


def test_sharding_requires_a_soft_target(tmp_path: Path) -> None:
    config = _base_config(
        tmp_path,
        sharding={"target_shard_bytes": None, "target_shard_lines": None},
    )
    with pytest.raises(ConfigError, match="target_shard"):
        _write_and_load(tmp_path, config)


def test_cli_shard_split(tmp_path: Path) -> None:
    config, config_path = _write_and_load(
        tmp_path,
        _base_config(tmp_path, sharding={"target_shard_bytes": 80}),
    )
    source = Path(config["paths"]["raw_log_dir"]) / "huge.log"
    body = _make_fixture(source, lines=100, line_bytes=40)
    code = pipeline_main(
        [
            "shard-split",
            "--config",
            str(config_path),
            "--input",
            str(source),
            "--run-id",
            "cli-run",
        ]
    )
    assert code == 0
    run_dir = Path(config["sharding"]["output_dir"]) / "cli-run"
    manifest = run_dir / "manifest.jsonl"
    assert manifest.is_file()
    records = read_manifest(manifest)
    rebuilt = b"".join(Path(r.shard_path).read_bytes() for r in records)
    assert rebuilt == body
