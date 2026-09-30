"""Phase 81 — journal_export normalize converter tests."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import yaml

from src.config import load_config, normalize_settings
from src.db.connection import get_connection
from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source
from src.normalize.persist import run_normalize
from src.normalize.registry import KNOWN_CONVERTERS
from src.normalize.writers import dead_letter_path

FIXTURE_JOURNAL = (
    Path(__file__).resolve().parent / "fixtures" / "normalize" / "sample.journal"
)


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
        "converters": [
            "gunzip",
            "bunzip2",
            "unzip",
            "tar",
            "evtx_text",
            "journal_export",
        ],
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
        "evtx": {"output_format": "text_oneline", "max_events": 500_000},
        "journal": {"output_format": "short_iso", "max_lines": 500_000},
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


def _write_and_load(tmp_path: Path, config: dict):
    path = tmp_path / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    loaded = load_config(path)
    get_connection(loaded).close()
    return loaded


def test_journal_export_in_registry() -> None:
    assert "journal_export" in KNOWN_CONVERTERS


def test_normalize_journal_unavailable_dead_letter(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    uploads.joinpath("sample.journal").write_bytes(FIXTURE_JOURNAL.read_bytes())

    loaded = _write_and_load(tmp_path, config)
    with mock.patch(
        "src.normalize.converters.journal_export.journalctl_available",
        return_value=False,
    ):
        summary = run_normalize(loaded)

    assert summary.dead_lettered == 1
    assert summary.converter_unavailable == 1
    dead = dead_letter_path(normalize_settings(loaded)).read_text(encoding="utf-8")
    assert "converter_unavailable" in dead
    assert "sample.journal" in dead


def test_normalize_journal_happy_path_mocked(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    journal_path = uploads / "sample.journal"
    journal_path.write_bytes(b"\x00binary-journal-placeholder\x00")
    source_bytes = journal_path.read_bytes()

    fake_out = (
        "2024-01-15T10:00:01+00:00 labhost systemd[1]: Started ssh.service "
        "_SYSTEMD_UNIT=ssh.service\n"
    )

    loaded = _write_and_load(tmp_path, config)
    with mock.patch(
        "src.normalize.converters.journal_export._run_journalctl",
        return_value=fake_out,
    ):
        summary = run_normalize(loaded)

    assert summary.files_converted == 1
    out = Path(config["normalize"]["output_dir"]) / "sample.journal.txt"
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert out.read_bytes() != source_bytes
    assert "_SYSTEMD_UNIT=ssh.service" in text

    first = text.splitlines()[0]
    source = resolve_log_source(out, first)
    assert source == "linux_journald"
    extraction = extract_entity_and_timestamp(first, source, default_year=2024)
    assert extraction.extraction_ok
    assert extraction.entity_id
    assert extraction.event_timestamp is not None
