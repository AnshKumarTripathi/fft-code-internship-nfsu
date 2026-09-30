"""Phase 85 — iptables / UFW and classic windows_pfirewall dialects."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.registry import REGISTERED_LOG_SOURCES
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source
from src.ingestion.persist import run_ingest
from src.ingestion.syslog_time import SyslogYearState
from src.parsing.persist import run_parse

UFW_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "network" / "ufw.log"
)
PFIREWALL_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "windows" / "pfirewall.log"
)
SSH_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "ssh_extended.log"
FILTERLOG_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "network" / "pfsense.txt"
)
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"

UFW_BLOCK = (
    "Jan 15 10:00:01 labhost kernel: [UFW BLOCK] IN=eth0 OUT= "
    "MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd "
    "SRC=10.0.0.1 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 "
    "PROTO=TCP SPT=443 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0"
)
PFSENSE = (
    "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
)
WIN_5156 = (
    "TimeCreated=2024-01-15T10:00:01.0000000Z EventID=5156 "
    "LogName=Microsoft-Windows-Windows Filtering Platform/Operational "
    "SourceAddress=10.0.0.1 DestAddress=10.0.0.2"
)
PFIREWALL_ROW = "2024-01-15 10:00:01 DROP TCP 10.0.0.1 10.0.0.2 54321 22 0 - - - - -"
PFIREWALL_FIELDS = (
    "#Fields: date time action protocol src-ip dst-ip src-port dst-port "
    "size tcpflags tcpsynack tcpsize tcpwindowstatus path"
)


def test_firewall_dialect_sources_registered() -> None:
    assert "iptables" in REGISTERED_LOG_SOURCES
    assert "windows_pfirewall" in REGISTERED_LOG_SOURCES
    assert len(REGISTERED_LOG_SOURCES) == 146


def test_ufw_iptables_extract() -> None:
    assert detect_log_source_from_line(UFW_BLOCK) == "iptables"
    result = extract_entity_and_timestamp(UFW_BLOCK, "iptables", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.1"
    assert result.entity_type == "ip"
    assert result.raw_fields["action"] == "deny"
    assert result.raw_fields["dst_ip"] == "10.0.0.2"
    assert result.raw_fields["dialect"] == "iptables"
    assert result.raw_fields["src_port"] == "443"
    assert result.raw_fields["dst_port"] == "22"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_pfirewall_extract() -> None:
    state = SyslogYearState(year=2024)
    header = extract_entity_and_timestamp(
        PFIREWALL_FIELDS, "windows_pfirewall", default_year=2024, year_state=state
    )
    assert header.extraction_ok is False
    assert state.pfirewall_fields is not None
    assert "src-ip" in state.pfirewall_fields

    result = extract_entity_and_timestamp(
        PFIREWALL_ROW, "windows_pfirewall", default_year=2024, year_state=state
    )
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.1"
    assert result.raw_fields["action"] == "deny"
    assert result.raw_fields["dialect"] == "pfirewall_file"
    assert result.raw_fields["dst_ip"] == "10.0.0.2"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_isolation_matrix() -> None:
    assert detect_log_source_from_line(PFSENSE) == "firewall"
    assert detect_log_source_from_line(UFW_BLOCK) == "iptables"
    assert detect_log_source_from_line(WIN_5156) == "windows_firewall"
    assert detect_log_source_from_line(PFIREWALL_ROW) == "windows_pfirewall"
    assert detect_log_source_from_line(PFSENSE) != "iptables"
    assert detect_log_source_from_line(WIN_5156) != "windows_pfirewall"
    assert resolve_log_source(Path("pfirewall.log"), "noise") == "windows_pfirewall"
    assert resolve_log_source(Path("ufw.log"), "noise") == "iptables"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(UFW_FIXTURE, raw / "ufw.log")
    if FILTERLOG_FIXTURE.is_file():
        shutil.copy(FILTERLOG_FIXTURE, raw / "pfsense.txt")
    else:
        (raw / "pfsense.txt").write_text(PFSENSE + "\n", encoding="utf-8")
    shutil.copy(PFIREWALL_FIXTURE, raw / "pfirewall.log")
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
        "ingestion": {
            "enabled_sources": [
                "ssh",
                "firewall",
                "iptables",
                "windows_pfirewall",
            ]
        },
    }


def test_mixed_firewall_dialects_parse_smoke(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    get_connection(config).close()
    ingest = run_ingest(config)
    assert ingest.lines_kept > 0
    summary = run_parse(config)
    assert summary.events_written > 0
    conn = get_connection(config)
    try:
        iptables = conn.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE log_source = 'iptables'"
        ).fetchone()
        firewall = conn.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE log_source = 'firewall'"
        ).fetchone()
        pfw = conn.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE log_source = 'windows_pfirewall'"
        ).fetchone()
        assert iptables is not None and int(iptables[0]) >= 2
        assert firewall is not None and int(firewall[0]) >= 1
        assert pfw is not None and int(pfw[0]) >= 3
    finally:
        conn.close()
