"""Bounded content-hash dedup: cap, spill, and Policy A duplicates."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.dedup import ContentHashSet
from src.ingestion.persist import run_ingest


def test_cap_spills_and_keeps_all_unique(tmp_path: Path) -> None:
    seen = ContentHashSet(memory_max=3, spill_dir=tmp_path)
    try:
        kept = 0
        for index in range(5):
            if seen.add(f"hash-{index}"):
                kept += 1
            assert seen.memory_size <= 3
        assert kept == 5
        assert seen.spilled is True
        assert seen.backend_used == "sqlite"
        assert seen.add("hash-0") is False
        assert seen.add("hash-4") is False
        assert seen.add("hash-5") is True
    finally:
        seen.close()


def test_identical_digest_dropped() -> None:
    seen = ContentHashSet(memory_max=10)
    try:
        assert seen.add("same") is True
        assert seen.add("same") is False
        assert seen.spilled is False
        assert seen.backend_used == "memory"
    finally:
        seen.close()


def test_sqlite_backend_from_start(tmp_path: Path) -> None:
    seen = ContentHashSet(memory_max=3, backend="sqlite", spill_dir=tmp_path)
    try:
        assert seen.spilled is True
        assert seen.backend_used == "sqlite"
        assert seen.memory_size == 0
        assert seen.add("a") is True
        assert seen.add("b") is True
        assert seen.add("a") is False
        assert seen.memory_size == 0
    finally:
        seen.close()


def _temp_config(tmp_path: Path, raw_text: str, ingestion: dict | None = None) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    (raw / "auth.log").write_text(raw_text, encoding="utf-8")
    config = {
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
    }
    if ingestion is not None:
        config["ingestion"] = ingestion
    return config


def test_ingest_cap_spills_and_keeps_unique_lines(tmp_path: Path) -> None:
    lines = [
        f"Jan 15 10:00:0{i} hostname sshd[{1000 + i}]: "
        f"Failed password for user{i} from 10.0.0.{i} port 22 ssh2"
        for i in range(5)
    ]
    lines.append(lines[0])  # true duplicate
    config = _temp_config(
        tmp_path,
        "\n".join(lines) + "\n",
        ingestion={
            "dedup_backend": "memory",
            "dedup_memory_max_hashes": 3,
            "syslog_year_policy": "carry",
        },
    )
    summary = run_ingest(config, config_path="test")
    assert summary.lines_read == 6
    assert summary.lines_kept == 5
    assert summary.lines_deduped == 1
    assert summary.dedup_spilled is True
    assert summary.dedup_backend_used == "sqlite"
    assert summary.year_policy == "carry"
    assert summary.extraction_ok_rate == 1.0


def test_ingest_sqlite_backend(tmp_path: Path) -> None:
    text = (
        "Jan 15 10:00:01 hostname sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2\n"
        "Jan 15 10:00:02 hostname sshd[2]: Failed password for bob from 1.2.3.5 port 1 ssh2\n"
    )
    config = _temp_config(
        tmp_path,
        text,
        ingestion={
            "dedup_backend": "sqlite",
            "dedup_memory_max_hashes": 3,
            "syslog_year_policy": "carry",
        },
    )
    summary = run_ingest(config, config_path="test")
    assert summary.lines_kept == 2
    assert summary.dedup_backend_used == "sqlite"
    assert summary.dedup_spilled is True
