"""Parametrized Unix OS / macOS subtype extractors (Phase 21)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.unix_os import UNIX_OS_LOG_SOURCES
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "unix_os"

_FILE_FOR_SOURCE = {
    "linux_syslog": "syslog.txt",
    "linux_kern": "kern.txt",
    "linux_dmesg": "dmesg.txt",
    "linux_journald": "journald.txt",
    "linux_cron": "cron.txt",
    "linux_package": "package.txt",
    "linux_auditd": "auditd.txt",
    "linux_boot": "boot.txt",
    "linux_mac": "mac.txt",
    "macos_unified": "macos_unified.txt",
    "macos_asl": "macos_asl.txt",
    "macos_install": "macos_install.txt",
}

# Dedicated modules cover auditd and mac.
SUBTYPES = tuple(
    source for source in sorted(_FILE_FOR_SOURCE) if source not in {"linux_auditd", "linux_mac"}
)


@pytest.mark.parametrize("log_source", SUBTYPES)
def test_subtype_fixture_extracts(log_source: str) -> None:
    path = FIXTURE_DIR / _FILE_FOR_SOURCE[log_source]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 10
    assert resolve_log_source(path, lines[0]) == log_source
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, log_source, default_year=2024)
        if result.extraction_ok:
            ok += 1
    assert ok >= 1


def test_all_unix_os_sources_have_fixtures() -> None:
    missing = [
        source
        for source in sorted(UNIX_OS_LOG_SOURCES)
        if not (FIXTURE_DIR / _FILE_FOR_SOURCE[source]).is_file()
    ]
    assert missing == []


def test_kern_vs_dmesg_rule() -> None:
    kern = "Jan 15 10:00:01 testhost kernel: USB disconnect, device number 4"
    dmesg = "[Mon Jan 15 10:00:01 2024] USB disconnect, device number 4"
    assert resolve_log_source(Path("messages"), kern) == "linux_kern"
    assert resolve_log_source(Path("messages"), dmesg) == "linux_dmesg"
