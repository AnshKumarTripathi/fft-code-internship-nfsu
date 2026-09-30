"""ingestion.enabled_sources allowlist (Phase 19)."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse

SSH_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "ssh_extended.log"
AUTH_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "linux_auth" / "authlog.log"
)
WIN_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "windows" / "security.txt"
)
AUDIT_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "unix_os" / "auditd.txt"
)
IDP_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "identity" / "idp.txt"
FW_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "network" / "pfsense.txt"
IDS_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "security" / "ids_ips.json"
)
ACCESS_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "logs"
    / "application"
    / "apache_combined.txt"
)
PG_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "database" / "postgres.txt"
CT_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "cloud" / "cloudtrail.json"
)
K8S_AUDIT_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "containers" / "k8s_audit.json"
)
SMTP_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "email" / "smtp.txt"
CICD_BUILD_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "cicd" / "jenkins.txt"
)
KAFKA_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "middleware" / "kafka.txt"
)
HYPERVISOR_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "virtualization" / "esxi.txt"
)
BADGE_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "physical" / "badge.csv"
)
VOIP_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "telephony" / "voip.txt"
)
PKI_CA_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "pki" / "pki_ca.json"
)
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"

SUDO = (
    "Jan 15 10:15:01 testhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
    "USER=root ; COMMAND=/bin/ls"
)
WIN_4624 = (
    "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
)


def _temp_config(tmp_path: Path, enabled_sources: list[str]) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(AUTH_FIXTURE, raw / "authlog.log")
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
        "ingestion": {"enabled_sources": enabled_sources},
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
        "_config_path": str(config_dir / "pipeline.yaml"),
    }


def test_dispatcher_disables_unlisted_source() -> None:
    result = extract_entity_and_timestamp(
        SUDO,
        "linux_auth",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: linux_auth" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_linux_auth(tmp_path: Path) -> None:
    config = _temp_config(tmp_path, ["ssh"])
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        count = connection.execute("SELECT COUNT(*) FROM parsed_events").fetchone()[0]
        assert count > 0
    finally:
        connection.close()


def test_dispatcher_disables_windows_security() -> None:
    result = extract_entity_and_timestamp(
        WIN_4624,
        "windows_security",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: windows_security" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_windows(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(WIN_FIXTURE, raw / "security.txt")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "windows_security" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_linux_auditd() -> None:
    audit = (
        'type=USER_AUTH msg=audit(1705312801.123:456): pid=1234 uid=0 auid=1000 '
        'exe="/usr/sbin/sshd" success=yes acct="alice"'
    )
    result = extract_entity_and_timestamp(
        audit,
        "linux_auditd",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: linux_auditd" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_linux_auditd(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(AUDIT_FIXTURE, raw / "audit.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "linux_auditd" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_idp() -> None:
    okta = (
        '{"uuid":"a1","published":"2024-01-15T10:00:01.000Z",'
        '"eventType":"user.session.start",'
        '"actor":{"alternateId":"alice@example.com"},'
        '"client":{"ipAddress":"10.0.0.8"},'
        '"outcome":{"result":"SUCCESS"}}'
    )
    result = extract_entity_and_timestamp(
        okta,
        "idp",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: idp" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_idp(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(IDP_FIXTURE, raw / "okta.json")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "idp" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_firewall() -> None:
    pfsense = (
        "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,"
        "0x0,,64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
    )
    result = extract_entity_and_timestamp(
        pfsense,
        "firewall",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: firewall" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_firewall(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(FW_FIXTURE, raw / "pfsense.txt")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "firewall" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_ids_ips() -> None:
    eve = (
        '{"timestamp":"2024-01-15T10:00:01.000000+0000","event_type":"alert",'
        '"src_ip":"10.0.0.8","dest_ip":"1.2.3.4",'
        '"alert":{"action":"blocked","severity":1}}'
    )
    result = extract_entity_and_timestamp(
        eve,
        "ids_ips",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: ids_ips" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_ids_ips(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(IDS_FIXTURE, raw / "eve.json")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "ids_ips" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_web_access() -> None:
    combined = (
        '10.0.0.8 - alice [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
    )
    result = extract_entity_and_timestamp(
        combined,
        "web_access",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: web_access" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_web_access(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(ACCESS_FIXTURE, raw / "access.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "web_access" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_db_postgres() -> None:
    postgres = (
        "2024-01-15 10:00:01.123 UTC [12345] alice@appdb LOG:  statement: SELECT 1"
    )
    result = extract_entity_and_timestamp(
        postgres,
        "db_postgres",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: db_postgres" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_db_postgres(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(PG_FIXTURE, raw / "postgres.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "db_postgres" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_aws_cloudtrail() -> None:
    trail = (
        '{"eventVersion":"1.09","eventTime":"2024-01-15T10:00:01Z",'
        '"eventSource":"iam.amazonaws.com","eventName":"ConsoleLogin",'
        '"userIdentity":{"type":"IAMUser","userName":"alice"},'
        '"sourceIPAddress":"10.0.0.8"}'
    )
    result = extract_entity_and_timestamp(
        trail,
        "aws_cloudtrail",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: aws_cloudtrail" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_aws_cloudtrail(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(CT_FIXTURE, raw / "cloudtrail.json")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "aws_cloudtrail" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_k8s_audit() -> None:
    audit = (
        '{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get",'
        '"user":{"username":"alice"},"sourceIPs":["10.0.0.8"],'
        '"requestReceivedTimestamp":"2024-01-15T10:00:01Z"}'
    )
    result = extract_entity_and_timestamp(
        audit,
        "k8s_audit",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: k8s_audit" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_k8s_audit(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(K8S_AUDIT_FIXTURE, raw / "k8s_audit.json")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "k8s_audit" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_smtp() -> None:
    smtp = "Jan 15 10:00:01 mail postfix/smtpd[1234]: connect from unknown[203.0.113.10]"
    result = extract_entity_and_timestamp(
        smtp,
        "smtp",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: smtp" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_smtp(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(SMTP_FIXTURE, raw / "smtp.txt")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "smtp" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_cicd_build() -> None:
    jenkins = "Started by user alice"
    result = extract_entity_and_timestamp(
        jenkins,
        "cicd_build",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: cicd_build" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_cicd_build(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(CICD_BUILD_FIXTURE, raw / "jenkins.txt")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "cicd_build" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_kafka() -> None:
    kafka = (
        "[2024-01-15 10:00:01,123] INFO [KafkaServer id=0] started "
        "(kafka.server.KafkaServer)"
    )
    result = extract_entity_and_timestamp(
        kafka,
        "kafka",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: kafka" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_kafka(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(KAFKA_FIXTURE, raw / "kafka.txt")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "kafka" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_hypervisor() -> None:
    esxi = "2024-01-15T10:00:01.123Z Hostd: [info] vm=web01 powered on host=esxi01"
    result = extract_entity_and_timestamp(
        esxi,
        "hypervisor",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: hypervisor" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_hypervisor(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(HYPERVISOR_FIXTURE, raw / "esxi.txt")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "hypervisor" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_badge() -> None:
    badge = "2024-01-15T10:00:01Z,B-1001,door-lobby,allow"
    result = extract_entity_and_timestamp(
        badge,
        "badge",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: badge" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_badge(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(BADGE_FIXTURE, raw / "badge.csv")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "badge" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_voip() -> None:
    voip = (
        "Jan 15 10:00:01 sip1 kamailio[9]: REGISTER sip:alice@example.com "
        "from 203.0.113.10 - 401 Unauthorized"
    )
    result = extract_entity_and_timestamp(
        voip,
        "voip",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: voip" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_voip(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(VOIP_FIXTURE, raw / "voip.txt")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "voip" not in sources
    finally:
        connection.close()


def test_dispatcher_disables_pki_ca() -> None:
    issued = (
        '{"cn":"web.example.com","action":"issued","user":"alice",'
        '"ts":"2024-01-15T10:00:01Z"}'
    )
    result = extract_entity_and_timestamp(
        issued,
        "pki_ca",
        default_year=2024,
        enabled_sources=["ssh"],
    )
    assert result.extraction_ok is False
    assert "source disabled: pki_ca" in (result.failure_reason or "")


def test_enabled_sources_ssh_only_hides_pki_ca(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(SSH_FIXTURE, raw / "ssh_extended.log")
    shutil.copy(PKI_CA_FIXTURE, raw / "pki_ca.json")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
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
        "ingestion": {"enabled_sources": ["ssh"]},
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
    config_path = str(config_dir / "pipeline.yaml")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)

    connection = get_connection(config)
    try:
        sources = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_source FROM parsed_events"
            ).fetchall()
        }
        assert sources == {"ssh"}
        assert "pki_ca" not in sources
    finally:
        connection.close()
