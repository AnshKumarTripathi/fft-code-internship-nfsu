"""Phase 82 — Snort fast-alert dialect under ids_ips."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "logs"
    / "security"
    / "snort_fast.alert"
)
SURICATA_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "security" / "ids_ips.json"
)
SSH_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "ssh_extended.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"

SNORT_LINE = (
    "01/15-10:00:01.123456  [**] [1:2001219:1] ET SCAN something [**] "
    "[Classification: Attempted Information Leak] [Priority: 2] "
    "{TCP} 10.0.0.1:54321 -> 10.0.0.2:22"
)
SURICATA = (
    '{"timestamp":"2024-01-15T10:00:01.000000+0000","flow_id":1,'
    '"event_type":"alert","src_ip":"10.0.0.8","src_port":54321,'
    '"dest_ip":"1.2.3.4","dest_port":22,"proto":"TCP",'
    '"alert":{"action":"allowed","signature":"ET SCAN SSH Brute Force","severity":2}}'
)
PFSENSE = (
    "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
)


def test_snort_fast_extract() -> None:
    assert resolve_log_source(Path("syslog"), SNORT_LINE) == "ids_ips"
    result = extract_entity_and_timestamp(SNORT_LINE, "ids_ips", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.1"
    assert result.entity_type == "ip"
    assert result.raw_fields["dialect"] == "snort_fast"
    assert result.raw_fields["dst_ip"] == "10.0.0.2"
    assert result.raw_fields["sid"] == "2001219"
    assert result.raw_fields["priority"] == "2"
    assert result.raw_fields["protocol"] == "TCP"
    assert result.raw_fields["src_port"] == "54321"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert result.event_timestamp.month == 1
    assert result.event_timestamp.day == 15


def test_snort_vs_suricata() -> None:
    assert detect_log_source_from_line(SURICATA) == "ids_ips"
    sur = extract_entity_and_timestamp(SURICATA, "ids_ips", default_year=2024)
    assert sur.raw_fields.get("dialect") == "suricata_eve"
    assert sur.entity_id == "10.0.0.8"

    assert detect_log_source_from_line(SNORT_LINE) == "ids_ips"
    snort = extract_entity_and_timestamp(SNORT_LINE, "ids_ips", default_year=2024)
    assert snort.raw_fields.get("dialect") == "snort_fast"


def test_snort_vs_firewall() -> None:
    assert detect_log_source_from_line(PFSENSE) == "firewall"
    assert detect_log_source_from_line(PFSENSE) != "ids_ips"
    assert resolve_log_source(Path("snort.alert"), PFSENSE) == "firewall"
    assert detect_log_source_from_line(SNORT_LINE) == "ids_ips"


def test_snort_filename_fallback() -> None:
    assert resolve_log_source(Path("snort_fast.alert"), "not a snort line") == "ids_ips"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(SURICATA_FIXTURE, raw / "eve.json")
    shutil.copy(FIXTURE, raw / "snort_fast.alert")
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
        "ingestion": {"enabled_sources": ["ssh", "ids_ips"]},
    }


def test_snort_parse_smoke(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    get_connection(config).close()
    ingest = run_ingest(config)
    assert ingest.lines_kept > 0
    summary = run_parse(config)
    assert summary.events_written > 0
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE log_source = 'ids_ips'"
        ).fetchone()
        assert rows is not None and int(rows[0]) > 0
    finally:
        conn.close()
