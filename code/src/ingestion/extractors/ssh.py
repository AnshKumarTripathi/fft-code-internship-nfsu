"""SSH / OpenSSH entity and field extraction."""

from __future__ import annotations

import re

from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import (
    YEAR_POLICY_CARRY,
    SyslogYearState,
    parse_syslog_timestamp,
)

# Keep v1 order: invalid-user before generic failed-password.
_SSH_INVALID_USER = re.compile(
    r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_INVALID_USER_DIRECT = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_FAILED = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_SESSION_OPENED = re.compile(r"session opened for user (?P<user>\S+)")
_SSH_SESSION_CLOSED = re.compile(r"session closed for user (?P<user>\S+)")
_SSH_DISCONNECT = re.compile(
    r"(?:Disconnected from|Connection closed by|Received disconnect from)"
    r"(?: (?:authenticating )?user (?P<user>\S+))?"
    r" (?P<ip>\S+)",
    re.IGNORECASE,
)
_SSH_RESET_PEER = re.compile(r"Connection reset by peer", re.IGNORECASE)
_SSH_RESET = re.compile(
    r"Connection reset by (?:(?:authenticating )?user (?P<user>\S+) )?(?P<ip>\S+)",
    re.IGNORECASE,
)
_SSH_MAX_ATTEMPTS = re.compile(
    r"maximum authentication attempts(?: exceeded)?(?: for (?P<user>\S+))?"
    r"(?: from (?P<ip>\S+))?",
    re.IGNORECASE,
)
_SSH_TOO_MANY = re.compile(
    r"Too many authentication failures for (?P<user>\S+)",
    re.IGNORECASE,
)
_SSH_NOT_ALLOWED = re.compile(
    r"User (?P<user>\S+)(?: from (?P<ip>\S+))? not allowed because",
    re.IGNORECASE,
)
_SSH_REFUSED = re.compile(r"refused connect from (?P<ip>\S+)", re.IGNORECASE)
_SSH_CONNECT_TO = re.compile(
    r"error: connect_to (?P<target>\S+)",
    re.IGNORECASE,
)
_SSH_NO_IDENT = re.compile(
    r"Did not receive identification string from (?P<ip>\S+)"
)
_SSH_BREAKIN = re.compile(r"POSSIBLE BREAK-IN ATTEMPT")
_SSH_REVERSE_MAP = re.compile(r"reverse mapping checking getaddrinfo")
_SSH_INPUT_INVALID = re.compile(
    r"input_userauth_request: invalid user (?P<user>\S+)"
)
_SSH_PAM = re.compile(r"pam_unix\(sshd:")
_PAM_USER = re.compile(r"\buser=(?P<user>\S+)")
_PAM_RHOST = re.compile(r"\brhost=(?P<ip>\S+)")
_BRACKET_IP = re.compile(r"(?<!sshd)\[(?P<ip>[^\]]+)\]")
_ADDRESS_IP = re.compile(r"\bAddress (?P<ip>\S+) maps to")
_SYSLOG_HOST = re.compile(
    r"^(?:(?P<year>\d{4})\s+)?"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\["
)
_MASKED_USERNAME = re.compile(r"^\*+$")


def extract_ssh(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract entity, timestamp, and SSH raw_fields from one line."""
    event_timestamp, ts_ok = parse_syslog_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname = _extract_hostname(line)
    match_result = _match_ssh(line)

    username = ""
    src_ip = ""
    auth_result = ""
    if match_result is not None:
        username, src_ip, auth_result = match_result

    raw_fields: dict = {}
    if username:
        raw_fields["username"] = username
    if src_ip:
        raw_fields["src_ip"] = src_ip
    if auth_result:
        raw_fields["auth_result"] = auth_result
    if hostname:
        raw_fields["hostname"] = hostname

    entity_id = username
    entity_type: str = "user"

    if entity_id and _MASKED_USERNAME.fullmatch(entity_id):
        raw_fields["masked_username"] = entity_id
        if src_ip:
            entity_id = src_ip
            entity_type = "ip"
        else:
            entity_id = ""
    elif not entity_id and src_ip:
        entity_id = src_ip
        entity_type = "ip"

    if not entity_id and hostname:
        entity_id = hostname
        entity_type = "host"

    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    if not entity_id:
        reason = (
            "no ssh auth pattern matched"
            if match_result is None
            else "no entity_id extracted"
        )
        return ExtractionResult(
            event_timestamp=event_timestamp,
            raw_fields=raw_fields,
            extraction_ok=False,
            failure_reason=reason,
        )

    return ExtractionResult(
        entity_id=entity_id,
        entity_type=entity_type,  # type: ignore[arg-type]
        event_timestamp=event_timestamp,
        raw_fields=raw_fields,
        extraction_ok=True,
        failure_reason=None if ts_ok else "timestamp parse failed",
    )


def _extract_hostname(line: str) -> str:
    match = _SYSLOG_HOST.match(line.strip())
    if not match:
        return ""
    return match.group("hostname")


def _clean_token(token: str | None) -> str:
    if not token:
        return ""
    cleaned = token.strip()
    # "Received disconnect from 1.2.3.4: 11:" — trim the delimiter, not IPv6 colons.
    if cleaned.endswith(":") and "." in cleaned:
        cleaned = cleaned[:-1]
    return cleaned


def _ip_from_breakin_or_reverse(line: str) -> str:
    bracket = _BRACKET_IP.search(line)
    if bracket:
        return _clean_token(bracket.group("ip"))
    address = _ADDRESS_IP.search(line)
    if address:
        return _clean_token(address.group("ip"))
    return ""


def _match_ssh(line: str) -> tuple[str, str, str] | None:
    invalid = _SSH_INVALID_USER.search(line)
    if invalid:
        return invalid.group("user"), _clean_token(invalid.group("ip")), "invalid_user"

    invalid_direct = _SSH_INVALID_USER_DIRECT.search(line)
    if invalid_direct:
        return (
            invalid_direct.group("user"),
            _clean_token(invalid_direct.group("ip")),
            "invalid_user",
        )

    failed = _SSH_FAILED.search(line)
    if failed:
        return failed.group("user"), _clean_token(failed.group("ip")), "failed"

    accepted = _SSH_ACCEPTED.search(line)
    if accepted:
        return accepted.group("user"), _clean_token(accepted.group("ip")), "accepted"

    max_attempts = _SSH_MAX_ATTEMPTS.search(line)
    if max_attempts:
        return (
            max_attempts.group("user") or "",
            _clean_token(max_attempts.group("ip")),
            "max_attempts",
        )

    too_many = _SSH_TOO_MANY.search(line)
    if too_many:
        return too_many.group("user"), "", "max_attempts"

    not_allowed = _SSH_NOT_ALLOWED.search(line)
    if not_allowed:
        return (
            not_allowed.group("user"),
            _clean_token(not_allowed.group("ip")),
            "not_allowed",
        )

    refused = _SSH_REFUSED.search(line)
    if refused:
        return "", _clean_token(refused.group("ip")), "refused"

    connect_to = _SSH_CONNECT_TO.search(line)
    if connect_to:
        target = _clean_token(connect_to.group("target"))
        if "." in target or ":" in target:
            return "", target, "connect_to"
        return "", "", "connect_to"

    if _SSH_RESET_PEER.search(line):
        return "", "", "disconnect"

    reset = _SSH_RESET.search(line)
    if reset:
        return (
            reset.group("user") or "",
            _clean_token(reset.group("ip")),
            "disconnect",
        )

    opened = _SSH_SESSION_OPENED.search(line)
    if opened:
        return opened.group("user"), "", "session_opened"

    closed = _SSH_SESSION_CLOSED.search(line)
    if closed:
        return closed.group("user"), "", "session_closed"

    disconnect = _SSH_DISCONNECT.search(line)
    if disconnect:
        return (
            disconnect.group("user") or "",
            _clean_token(disconnect.group("ip")),
            "disconnect",
        )

    no_ident = _SSH_NO_IDENT.search(line)
    if no_ident:
        return "", _clean_token(no_ident.group("ip")), "no_ident"

    if _SSH_BREAKIN.search(line):
        return "", _ip_from_breakin_or_reverse(line), "breakin"

    if _SSH_REVERSE_MAP.search(line):
        return "", _ip_from_breakin_or_reverse(line), "reverse_map"

    input_invalid = _SSH_INPUT_INVALID.search(line)
    if input_invalid:
        return input_invalid.group("user"), "", "invalid_user"

    if _SSH_PAM.search(line):
        pam_user = _PAM_USER.search(line)
        pam_host = _PAM_RHOST.search(line)
        username = pam_user.group("user") if pam_user else ""
        src_ip = _clean_token(pam_host.group("ip") if pam_host else "")
        return username, src_ip, "pam"

    return None
