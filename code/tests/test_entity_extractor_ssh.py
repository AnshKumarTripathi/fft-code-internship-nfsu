"""Unit tests for SSH entity / timestamp extraction."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp


def test_failed_password_extracts_user_and_ip() -> None:
    line = (
        "Jan 15 10:00:01 hostname sshd[1234]: "
        "Failed password for alice from 192.168.1.10 port 51234 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "192.168.1.10"
    assert result.raw_fields["auth_result"] == "failed"
    assert result.raw_fields["hostname"] == "hostname"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert result.event_timestamp.month == 1
    assert result.event_timestamp.day == 15
    assert result.event_timestamp.hour == 10


def test_invalid_user_pattern() -> None:
    line = (
        "Feb 1 08:15:31 host sshd[1]: "
        "Failed password for invalid user admin from 198.51.100.1 port 1 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2025)
    assert result.extraction_ok is True
    assert result.entity_id == "admin"
    assert result.raw_fields["auth_result"] == "invalid_user"
    assert result.raw_fields["src_ip"] == "198.51.100.1"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2025


def test_accepted_password() -> None:
    line = (
        "Mar 10 23:59:59 host sshd[2]: "
        "Accepted password for eve from 192.0.2.50 port 5555 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "eve"
    assert result.raw_fields["auth_result"] == "accepted"


def test_missing_year_uses_default_year() -> None:
    line = "Jan 5 12:34:56 host sshd[3]: Failed password for bob from 10.0.0.1 port 1 ssh2"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2023)
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2023
    assert result.event_timestamp.month == 1
    assert result.event_timestamp.day == 5


def test_invalid_user_direct_pattern() -> None:
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "webmaster"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "173.234.31.186"
    assert result.raw_fields["auth_result"] == "invalid_user"
    assert result.raw_fields["hostname"] == "LabSZ"
    assert result.event_timestamp is not None


def test_masked_username_maps_to_src_ip() -> None:
    """LogHub OpenSSH uses ***** as a masked probe username."""
    line = (
        "Dec 17 09:40:30 LabSZ sshd[31466]: "
        "Failed password for invalid user ***** from 103.207.39.38 port 55106 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "103.207.39.38"
    assert result.entity_type == "ip"
    assert result.raw_fields["username"] == "*****"
    assert result.raw_fields["masked_username"] == "*****"
    assert result.raw_fields["src_ip"] == "103.207.39.38"


def test_accepted_publickey() -> None:
    line = (
        "Jan 5 12:00:00 host sshd[9]: "
        "Accepted publickey for alice from 10.0.0.2 port 22 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["auth_result"] == "accepted"


def test_unsupported_log_source() -> None:
    result = extract_entity_and_timestamp("anything", "not_a_real_source", default_year=2024)
    assert result.extraction_ok is False
    assert "unsupported" in (result.failure_reason or "")


def test_non_matching_ssh_line() -> None:
    line = "Jan 15 11:00:00 hostname kernel: something unrelated"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is False
    assert result.event_timestamp is not None
    assert "no ssh auth pattern" in (result.failure_reason or "")
