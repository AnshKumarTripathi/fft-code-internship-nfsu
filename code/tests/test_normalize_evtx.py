"""Phase 81 — EVTX normalize converter tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.config import load_config, normalize_settings
from src.db.connection import get_connection
from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source
from src.normalize.converters.evtx_text import event_xml_to_oneline
from src.normalize.persist import run_normalize
from src.normalize.registry import KNOWN_CONVERTERS
from src.normalize.writers import dead_letter_path

FIXTURE_EVTX = (
    Path(__file__).resolve().parent / "fixtures" / "normalize" / "sample_security.evtx"
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


def test_evtx_text_in_registry() -> None:
    assert "evtx_text" in KNOWN_CONVERTERS


def test_event_xml_to_oneline_dialect() -> None:
    xml = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2024-01-15 10:00:01.000000+00:00"/>
    <Channel>Security</Channel>
    <Computer>WIN-DC01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
  </EventData>
</Event>
"""
    line = event_xml_to_oneline(xml)
    assert "TimeCreated=2024-01-15T10:00:01.000Z" in line
    assert "EventID=4624" in line
    assert "LogName=Security" in line
    assert "Computer=WIN-DC01" in line
    assert "TargetUserName=alice" in line
    assert "\n" not in line


@pytest.mark.skipif(not FIXTURE_EVTX.is_file(), reason="sample_security.evtx missing")
def test_normalize_evtx_happy_path(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    dest = uploads / "sample_security.evtx"
    dest.write_bytes(FIXTURE_EVTX.read_bytes())
    source_bytes = dest.read_bytes()

    loaded = _write_and_load(tmp_path, config)
    summary = run_normalize(loaded)
    assert summary.files_converted == 1
    assert summary.files_out == 1

    out = Path(config["normalize"]["output_dir"]) / "sample_security.evtx.txt"
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert text.strip()
    assert out.read_bytes() != source_bytes  # rename-only guard
    assert "EventID=" in text
    assert "TimeCreated=" in text

    first = text.splitlines()[0]
    source = resolve_log_source(out, first)
    assert source == "windows_security"
    extraction = extract_entity_and_timestamp(first, source, default_year=2017)
    assert extraction.extraction_ok
    assert extraction.entity_id
    assert extraction.event_timestamp is not None


@pytest.mark.skipif(not FIXTURE_EVTX.is_file(), reason="sample_security.evtx missing")
def test_normalize_evtx_corrupt_dead_letter(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    uploads = Path(config["pipeline_ui"]["upload_dir"])
    # ElfFile magic but truncated / garbage body
    (uploads / "broken.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)

    loaded = _write_and_load(tmp_path, config)
    summary = run_normalize(loaded)
    assert summary.dead_lettered >= 1
    dead = dead_letter_path(normalize_settings(loaded)).read_text(encoding="utf-8")
    assert "broken.evtx" in dead
