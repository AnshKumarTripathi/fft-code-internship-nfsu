"""Phase 83 — Zeek conn/dns TSV extractors."""

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

CONN_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "zeek" / "conn.log"
DNS_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "zeek" / "dns.log"
SSH_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "ssh_extended.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"

CONN_FIELDS = (
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice"
    "\tduration\torig_bytes\tresp_bytes\tconn_state"
)
DNS_FIELDS = (
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id"
    "\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name"
)
CONN_ROW = (
    "1705312801.123456\tCaaaaa11111\t10.0.0.8\t54321\t1.2.3.4\t22\ttcp\tssh"
    "\t1.5\t200\t1500\tSF"
)
DNS_ROW = (
    "1705312801.111111\tCddddd44444\t10.0.0.8\t53001\t8.8.8.8\t53\tudp\t1"
    "\t0.01\texample.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR"
)
SQUID = (
    "1705312801.0 10 10.0.0.8 TCP_MISS/200 123 GET http://example.com/ - "
    "DIRECT/93.184.216.34 text/html"
)
SURICATA = (
    '{"timestamp":"2024-01-15T10:00:01.000000+0000","event_type":"alert",'
    '"src_ip":"10.0.0.8","dest_ip":"1.2.3.4",'
    '"alert":{"action":"blocked","severity":1,"signature":"ET SCAN"}}'
)
APACHE = (
    '10.0.0.8 - - [15/Jan/2024:10:00:01 +0000] '
    '"GET /index.html HTTP/1.1" 200 1234'
)


def test_zeek_sources_registered() -> None:
    assert "zeek_conn" in REGISTERED_LOG_SOURCES
    assert "zeek_dns" in REGISTERED_LOG_SOURCES
    assert len(REGISTERED_LOG_SOURCES) == 146


def test_zeek_conn_extract() -> None:
    state = SyslogYearState(year=2024)
    assert resolve_log_source(Path("conn.log"), CONN_FIELDS) == "zeek_conn"
    header = extract_entity_and_timestamp(
        CONN_FIELDS, "zeek_conn", default_year=2024, year_state=state
    )
    assert header.extraction_ok is False
    assert state.zeek_fields is not None
    assert "id.orig_h" in state.zeek_fields

    result = extract_entity_and_timestamp(
        CONN_ROW, "zeek_conn", default_year=2024, year_state=state
    )
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.8"
    assert result.entity_type == "ip"
    assert result.raw_fields["dst_ip"] == "1.2.3.4"
    assert result.raw_fields["dialect"] == "zeek_conn"
    assert result.raw_fields["protocol"] == "tcp"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_zeek_dns_extract() -> None:
    state = SyslogYearState(year=2024)
    extract_entity_and_timestamp(
        DNS_FIELDS, "zeek_dns", default_year=2024, year_state=state
    )
    result = extract_entity_and_timestamp(
        DNS_ROW, "zeek_dns", default_year=2024, year_state=state
    )
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.8"
    assert result.raw_fields["query"] == "example.com"
    assert result.raw_fields["dialect"] == "zeek_dns"
    assert result.event_timestamp is not None


def test_zeek_isolation_vs_proxy_ids_web() -> None:
    assert detect_log_source_from_line(SQUID) != "zeek_conn"
    assert detect_log_source_from_line(SURICATA) == "ids_ips"
    assert detect_log_source_from_line(APACHE) != "zeek_conn"
    assert resolve_log_source(Path("access.log"), APACHE) != "zeek_conn"
    assert resolve_log_source(Path("conn.log"), CONN_ROW) == "zeek_conn"
    assert resolve_log_source(Path("dns.log"), DNS_ROW) == "zeek_dns"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(CONN_FIXTURE, raw / "conn.log")
    shutil.copy(DNS_FIXTURE, raw / "dns.log")
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
        "ingestion": {"enabled_sources": ["ssh", "zeek_conn", "zeek_dns"]},
    }


def test_zeek_parse_smoke(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    get_connection(config).close()
    ingest = run_ingest(config)
    assert ingest.lines_kept > 0
    summary = run_parse(config)
    assert summary.events_written > 0
    conn = get_connection(config)
    try:
        conn_count = conn.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE log_source = 'zeek_conn'"
        ).fetchone()
        dns_count = conn.execute(
            "SELECT COUNT(*) FROM parsed_events WHERE log_source = 'zeek_dns'"
        ).fetchone()
        assert conn_count is not None and int(conn_count[0]) >= 3
        assert dns_count is not None and int(dns_count[0]) >= 3
    finally:
        conn.close()
