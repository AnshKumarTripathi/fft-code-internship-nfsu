"""Phase 84 — Common Event Format (CEF) extractor."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.registry import REGISTERED_LOG_SOURCES
from src.ingestion.extractors.security.cef import parse_cef_extensions, unescape_cef
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse

FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "security" / "sample.cef"
)
SSH_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "ssh_extended.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"

CEF_LINE = (
    "CEF:0|Security|ThreatAmp|1.0|100|Login success|3|"
    "src=10.0.0.8 dst=10.0.0.2 suser=alice rt=Jan 15 2024 10:00:01"
)
CEF_ESCAPED = (
    "CEF:0|Security|ThreatAmp|1.0|300|Escaped equals|5|"
    "src=10.0.0.8 msg=key\\=value still here dst=10.0.0.2 rt=1705312803000"
)
SIEM_JSON = (
    '{"timestamp":"2024-01-15T10:00:01Z","rule_name":"brute",'
    '"siem":"splunk","user":"alice","src_ip":"10.0.0.8","action":"correlated"}'
)
SYSLOG = "Jan 15 10:00:01 labhost sshd[1]: Accepted password for alice from 10.0.0.8"


def test_cef_registered() -> None:
    assert "cef" in REGISTERED_LOG_SOURCES
    assert len(REGISTERED_LOG_SOURCES) == 146


def test_cef_extract() -> None:
    assert resolve_log_source(Path("events.cef"), CEF_LINE) == "cef"
    result = extract_entity_and_timestamp(CEF_LINE, "cef", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["dialect"] == "cef"
    assert result.raw_fields["vendor"] == "Security"
    assert result.raw_fields["product"] == "ThreatAmp"
    assert result.raw_fields["signature_id"] == "100"
    assert result.raw_fields["name"] == "Login success"
    assert result.raw_fields["severity"] == "3"
    assert result.raw_fields["src_ip"] == "10.0.0.8"
    assert result.raw_fields["dst_ip"] == "10.0.0.2"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert result.event_timestamp.month == 1
    assert result.event_timestamp.day == 15


def test_cef_escape_equals_not_truncated() -> None:
    assert unescape_cef(r"key\=value") == "key=value"
    fields = parse_cef_extensions(r"src=10.0.0.8 msg=key\=value still here dst=10.0.0.2")
    assert fields["msg"] == "key=value still here"
    assert fields["dst"] == "10.0.0.2"
    result = extract_entity_and_timestamp(CEF_ESCAPED, "cef", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.8"
    assert result.raw_fields["dst_ip"] == "10.0.0.2"


def test_cef_isolation_vs_siem_syslog() -> None:
    assert detect_log_source_from_line(SIEM_JSON) == "siem"
    assert detect_log_source_from_line(SIEM_JSON) != "cef"
    assert detect_log_source_from_line(SYSLOG) != "cef"
    assert detect_log_source_from_line(CEF_LINE) == "cef"
    assert resolve_log_source(Path("siem.json"), SIEM_JSON) == "siem"


def test_cef_filename_fallback() -> None:
    assert resolve_log_source(Path("events.cef"), "not a cef line") == "cef"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(FIXTURE, raw / "sample.cef")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "parse": {"mode": "train_and_snapshot", "start_empty": True},
        "ingestion": {"enabled_sources": ["ssh", "cef"]},
    }


def test_cef_parse_smoke(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    get_connection(config).close()
    ingest = run_ingest(config)
    assert ingest.lines_kept > 0
    summary = run_parse(config)
    assert summary.events_written > 0
    conn = get_connection(config)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE log_source = 'cef'"
        ).fetchone()
        assert count is not None and int(count[0]) >= 3
    finally:
        conn.close()
