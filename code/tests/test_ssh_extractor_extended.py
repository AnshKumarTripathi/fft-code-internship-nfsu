"""Extended SSH extractor coverage (Phase 12 patterns, hostname, host entity)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp


def test_labsz_failed_password_sets_hostname() -> None:
    line = "Dec 10 06:55:46 LabSZ sshd[1]: Failed password for alice from 1.2.3.4"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.raw_fields["hostname"] == "LabSZ"
    assert result.raw_fields["username"] == "alice"
    assert result.entity_type == "user"


def test_hostname_only_sshd_line_is_host_entity() -> None:
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: error: bind: Address already in use"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "LabSZ"
    assert result.entity_type == "host"
    assert result.raw_fields["hostname"] == "LabSZ"


def test_masked_username_still_maps_to_ip() -> None:
    line = (
        "Dec 17 09:40:30 LabSZ sshd[31466]: "
        "Failed password for invalid user ***** from 103.207.39.38 port 55106 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "103.207.39.38"
    assert result.entity_type == "ip"
    assert result.raw_fields["masked_username"] == "*****"
    assert result.raw_fields["hostname"] == "LabSZ"


def test_session_opened_extracts_user() -> None:
    line = (
        "Jan 15 10:04:00 hostname sshd[1234]: "
        "pam_unix(sshd:session): session opened for user alice by (uid=0)"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["auth_result"] == "session_opened"
    assert result.raw_fields["hostname"] == "hostname"


def test_session_closed_extracts_user() -> None:
    line = (
        "Jan 15 10:05:00 hostname sshd[1234]: "
        "pam_unix(sshd:session): session closed for user alice"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["auth_result"] == "session_closed"


def test_connection_closed_by_ip() -> None:
    line = "Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "173.234.31.186"
    assert result.entity_type == "ip"
    assert result.raw_fields["auth_result"] == "disconnect"


def test_received_disconnect_from_ip() -> None:
    line = (
        "Dec 10 07:07:45 LabSZ sshd[24206]: "
        "Received disconnect from 52.80.34.196: 11: Bye Bye [preauth]"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "52.80.34.196"
    assert result.entity_type == "ip"
    assert result.raw_fields["auth_result"] == "disconnect"


def test_disconnected_from_user_and_ip() -> None:
    line = (
        "Jan 15 10:06:00 hostname sshd[9]: "
        "Disconnected from user alice 192.168.1.10 port 51234"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "192.168.1.10"
    assert result.raw_fields["auth_result"] == "disconnect"


def test_no_ident_uses_ip() -> None:
    line = (
        "Jan 15 10:07:00 hostname sshd[10]: "
        "Did not receive identification string from 198.51.100.9"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "198.51.100.9"
    assert result.entity_type == "ip"
    assert result.raw_fields["auth_result"] == "no_ident"


def test_combined_reverse_map_breakin_is_breakin() -> None:
    line = (
        "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo "
        "for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "173.234.31.186"
    assert result.entity_type == "ip"
    assert result.raw_fields["auth_result"] == "breakin"
    assert result.raw_fields["hostname"] == "LabSZ"


def test_reverse_map_without_breakin() -> None:
    line = (
        "Dec 10 06:55:46 LabSZ sshd[1]: reverse mapping checking getaddrinfo "
        "for ns.example.com [10.0.0.8] failed"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.8"
    assert result.raw_fields["auth_result"] == "reverse_map"


def test_input_userauth_invalid_user() -> None:
    line = (
        "Dec 10 06:55:46 LabSZ sshd[24200]: "
        "input_userauth_request: invalid user webmaster [preauth]"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "webmaster"
    assert result.entity_type == "user"
    assert result.raw_fields["auth_result"] == "invalid_user"


def test_pam_auth_failure_user_and_rhost() -> None:
    line = (
        "Dec 10 07:13:31 LabSZ sshd[24227]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=5.36.59.76  user=root"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "root"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "5.36.59.76"
    assert result.raw_fields["auth_result"] == "pam"


def test_pam_check_pass_user_unknown_falls_back_to_host() -> None:
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2015)
    assert result.extraction_ok is True
    assert result.entity_id == "LabSZ"
    assert result.entity_type == "host"
    assert result.raw_fields["auth_result"] == "pam"


def test_kernel_line_still_fails() -> None:
    line = "Jan 15 11:00:00 hostname kernel: something unrelated"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is False
    assert "no ssh auth pattern" in (result.failure_reason or "")
    assert "hostname" not in result.raw_fields


def test_maximum_authentication_attempts() -> None:
    line = (
        "Jan 15 10:08:00 hostname sshd[12]: "
        "Disconnecting authenticating user alice 192.168.1.10 port 22: "
        "Too many authentication failures for alice [preauth]"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["auth_result"] == "max_attempts"


def test_maximum_authentication_attempts_from_ip() -> None:
    line = (
        "Jan 15 10:08:01 hostname sshd[13]: "
        "error: maximum authentication attempts exceeded for bob from 10.0.0.9 port 22 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "bob"
    assert result.raw_fields["src_ip"] == "10.0.0.9"
    assert result.raw_fields["auth_result"] == "max_attempts"


def test_user_not_allowed_because() -> None:
    line = (
        "Jan 15 10:09:00 hostname sshd[14]: "
        "User carol from 198.51.100.2 not allowed because not listed in AllowUsers"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "carol"
    assert result.raw_fields["src_ip"] == "198.51.100.2"
    assert result.raw_fields["auth_result"] == "not_allowed"


def test_connection_reset_by_ip() -> None:
    line = "Jan 15 10:10:00 hostname sshd[15]: Connection reset by 203.0.113.9 port 22 [preauth]"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "203.0.113.9"
    assert result.entity_type == "ip"
    assert result.raw_fields["auth_result"] == "disconnect"


def test_connection_reset_by_peer_uses_host() -> None:
    line = "Jan 15 10:10:01 hostname sshd[16]: fatal: Read from socket failed: Connection reset by peer [preauth]"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "hostname"
    assert result.entity_type == "host"
    assert result.raw_fields["auth_result"] == "disconnect"


def test_refused_connect_from() -> None:
    line = "Jan 15 10:11:00 hostname sshd[17]: refused connect from 192.0.2.80"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "192.0.2.80"
    assert result.raw_fields["auth_result"] == "refused"


def test_error_connect_to() -> None:
    line = "Jan 15 10:12:00 hostname sshd[18]: error: connect_to 10.1.2.3 port 22: failed"
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "10.1.2.3"
    assert result.raw_fields["auth_result"] == "connect_to"


def test_accepted_keyboard_interactive_without_pam_suffix() -> None:
    line = (
        "Jan 15 10:13:00 hostname sshd[19]: "
        "Accepted keyboard-interactive for alice from 192.168.1.10 port 22 ssh2"
    )
    result = extract_entity_and_timestamp(line, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["auth_result"] == "accepted"
    assert result.raw_fields["src_ip"] == "192.168.1.10"
