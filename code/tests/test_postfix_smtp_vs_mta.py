"""Postfix program split: smtpd/smtp → smtp, qmgr/pickup/cleanup → mta (Phase 29)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

SMTPD = "Jan 15 10:00:01 mail postfix/smtpd[1234]: connect from unknown[203.0.113.10]"
SMTP_CLIENT = (
    "Jan 15 10:00:07 mail postfix/smtp[2345]: 4F8A3: to=<carol@example.com>, "
    "relay=mx.example.com[198.51.100.30]:25, delay=0.12, status=sent (250 2.0.0 Ok)"
)
SASL = (
    "Jan 15 10:00:03 mail postfix/smtpd[1234]: 4F8A3: client=unknown[203.0.113.10], "
    "sasl_method=PLAIN, sasl_username=alice"
)
SASL_FAIL = (
    "Jan 15 10:00:04 mail postfix/smtpd[1234]: warning: unknown[203.0.113.11]: "
    "SASL PLAIN authentication failed"
)
QMGR = (
    "Jan 15 10:00:01 mail postfix/qmgr[99]: 4F8A3: from=<alice@example.com>, "
    "size=1234, nrcpt=1 (queue active)"
)
PICKUP = "Jan 15 10:00:03 mail postfix/pickup[77]: 4F8A5: uid=1000 from=<carol>"
CLEANUP = "Jan 15 10:00:05 mail postfix/cleanup[88]: 4F8A3: message-id=<id1@example.com>"
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"


def test_smtpd_is_smtp() -> None:
    assert detect_log_source_from_line(SMTPD) == "smtp"
    assert resolve_log_source(Path("syslog.log"), SMTPD) == "smtp"


def test_postfix_smtp_client_is_smtp() -> None:
    assert detect_log_source_from_line(SMTP_CLIENT) == "smtp"


def test_qmgr_pickup_cleanup_are_mta() -> None:
    assert detect_log_source_from_line(QMGR) == "mta"
    assert detect_log_source_from_line(PICKUP) == "mta"
    assert detect_log_source_from_line(CLEANUP) == "mta"
    assert resolve_log_source(Path("smtp.txt"), QMGR) == "mta"


def test_generic_syslog_stays_linux_syslog() -> None:
    assert detect_log_source_from_line(SYSLOG) == "linux_syslog"
    assert resolve_log_source(Path("smtp.txt"), SYSLOG) == "linux_syslog"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("smtp.txt")) == "smtp"
    assert detect_log_source(Path("mta.txt")) == "mta"
    assert detect_log_source(Path("syslog.log")) == "linux_syslog"
    assert detect_log_source(Path("mail.log")) not in {"smtp", "mta", "mail_gateway"}


def test_sasl_extracts_user_ip_and_auth_result() -> None:
    result = extract_entity_and_timestamp(SASL, "smtp", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields.get("src_ip") == "203.0.113.10"
    assert result.raw_fields.get("auth_result") == "success"


def test_sasl_failure_sets_auth_result() -> None:
    result = extract_entity_and_timestamp(SASL_FAIL, "smtp", default_year=2024)
    assert result.extraction_ok is True
    assert result.raw_fields.get("src_ip") == "203.0.113.11"
    assert result.raw_fields.get("auth_result") == "failure"
