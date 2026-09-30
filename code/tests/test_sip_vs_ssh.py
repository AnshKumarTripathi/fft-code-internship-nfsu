"""SIP vs SSH isolation and REGISTER auth_result (Phase 34)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

SSH = (
    "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 22 ssh2"
)
SIP_FAIL = (
    "Jan 15 10:00:01 sip1 kamailio[9]: REGISTER sip:alice@example.com "
    "from 203.0.113.10 - 401 Unauthorized"
)
SIP_OK = (
    "Jan 15 10:00:02 sip1 kamailio[9]: REGISTER sip:alice@example.com "
    "from 10.0.0.8 - 200 OK"
)
SIP_MIXED = (
    "Jan 15 10:00:01 sip1 kamailio[9]: REGISTER sip:alice@example.com "
    "Failed password for alice from 1.2.3.4"
)
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"
APP_RUNTIME = '{"level":"info","msg":"hello","ts":"2024-01-15T10:00:01Z"}'


def test_ssh_failed_password_stays_ssh() -> None:
    assert detect_log_source_from_line(SSH) == "ssh"
    assert resolve_log_source(Path("voip.txt"), SSH) == "ssh"


def test_sip_register_is_voip_even_in_auth_log() -> None:
    assert detect_log_source_from_line(SIP_FAIL) == "voip"
    assert resolve_log_source(Path("auth.log"), SIP_FAIL) == "voip"
    assert resolve_log_source(Path("syslog.log"), SIP_FAIL) == "voip"


def test_sip_markers_win_over_failed_password_phrase() -> None:
    assert detect_log_source_from_line(SIP_MIXED) == "voip"


def test_register_fail_sets_auth_result_failure() -> None:
    result = extract_entity_and_timestamp(SIP_FAIL, "voip", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_type in {"user", "ip"}
    assert result.entity_id in {"alice", "203.0.113.10"}
    assert result.raw_fields.get("auth_result") == "failure"


def test_register_ok_sets_auth_result_success() -> None:
    result = extract_entity_and_timestamp(SIP_OK, "voip", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields.get("auth_result") == "success"


def test_generic_syslog_and_json_not_voip() -> None:
    assert detect_log_source_from_line(SYSLOG) == "linux_syslog"
    assert resolve_log_source(Path("voip.txt"), SYSLOG) == "linux_syslog"
    assert detect_log_source_from_line(APP_RUNTIME) == "app_runtime"
    assert detect_log_source(Path("voip.txt")) == "voip"
    assert detect_log_source(Path("syslog.log")) == "linux_syslog"
