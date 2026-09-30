"""Web access vs SSH marker isolation (Phase 25)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

SSH_FAIL = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"
SSH_FROM = "Dec 10 06:55:46 LabSZ Invalid user x from 1.1.1.1"
COMBINED = (
    '10.0.0.8 - alice [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
)


def test_ssh_not_web_access() -> None:
    assert detect_log_source_from_line(SSH_FAIL) == "ssh"
    assert detect_log_source_from_line(SSH_FROM) == "ssh"
    assert resolve_log_source(Path("access.log"), SSH_FAIL) == "ssh"
    assert resolve_log_source(Path("auth.log"), SSH_FROM) == "ssh"


def test_combined_not_ssh() -> None:
    assert detect_log_source_from_line(COMBINED) == "web_access"
    assert resolve_log_source(Path("auth.log"), COMBINED) == "web_access"


def test_auth_log_filename_stays_ssh() -> None:
    assert detect_log_source(Path("auth.log")) == "ssh"
    assert detect_log_source(Path("access.log")) == "web_access"
