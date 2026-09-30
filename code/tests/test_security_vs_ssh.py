"""Security appliances vs SSH marker isolation (Phase 24)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

SSH_FAIL = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"
SSH_ACCEPT = (
    "Jan 15 10:00:02 testhost sshd[1]: Accepted publickey for alice from 1.2.3.4 "
    "port 22 ssh2"
)
EVE = (
    '{"timestamp":"2024-01-15T10:00:01.000000+0000","event_type":"alert",'
    '"src_ip":"10.0.0.8","dest_ip":"1.2.3.4",'
    '"alert":{"action":"blocked","severity":1}}'
)
EDR = (
    '{"timestamp":"2024-01-15T10:00:01.000Z","event_simpleName":"ProcessRollup2",'
    '"ComputerName":"WIN-WS01","UserName":"alice"}'
)


def test_ssh_not_ids_or_edr() -> None:
    assert detect_log_source_from_line(SSH_FAIL) == "ssh"
    assert detect_log_source_from_line(SSH_ACCEPT) == "ssh"
    assert resolve_log_source(Path("eve.json"), SSH_FAIL) == "ssh"
    assert resolve_log_source(Path("edr.txt"), SSH_FAIL) == "ssh"


def test_suricata_and_edr_not_ssh() -> None:
    assert detect_log_source_from_line(EVE) == "ids_ips"
    assert detect_log_source_from_line(EDR) == "edr"
    assert resolve_log_source(Path("auth.log"), EVE) == "ids_ips"
