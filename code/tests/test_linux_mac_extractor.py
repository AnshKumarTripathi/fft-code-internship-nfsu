"""linux_mac (SELinux / AppArmor) extractor tests (Phase 21)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "unix_os" / "mac.txt"

AVC = (
    "Jan 15 10:00:01 testhost kernel: avc:  denied  { read } for  pid=123 "
    'comm="httpd" scontext=system_u:system_r:httpd_t:s0 '
    "tcontext=system_u:object_r:etc_t:s0 tclass=file"
)
APPARMOR = (
    "Jan 15 10:00:03 testhost kernel: apparmor=\"DENIED\" operation=\"open\" "
    'profile="/usr/bin/foo" name="/etc/shadow" pid=200 comm="foo"'
)
KERN = "Jan 15 10:00:01 testhost kernel: USB disconnect, device number 4"
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"


def test_avc_denied_is_linux_mac_not_syslog_or_kern() -> None:
    assert resolve_log_source(Path("syslog"), AVC) == "linux_mac"
    assert resolve_log_source(Path("kern.log"), AVC) == "linux_mac"
    result = extract_entity_and_timestamp(AVC, "linux_mac", default_year=2024)
    assert result.extraction_ok is True
    assert result.raw_fields["hostname"] == "testhost"
    assert "httpd_t" in result.raw_fields["avc_scontext"]


def test_apparmor_denied_is_linux_mac() -> None:
    assert resolve_log_source(Path("syslog"), APPARMOR) == "linux_mac"
    result = extract_entity_and_timestamp(APPARMOR, "linux_mac", default_year=2024)
    assert result.extraction_ok is True
    assert result.raw_fields["apparmor_profile"] == "/usr/bin/foo"


def test_plain_kernel_is_not_mac() -> None:
    assert resolve_log_source(Path("kern.log"), KERN) == "linux_kern"
    assert resolve_log_source(Path("syslog"), SYSLOG) == "linux_syslog"


def test_mac_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "linux_mac", default_year=2024).extraction_ok
        for line in lines
    )
