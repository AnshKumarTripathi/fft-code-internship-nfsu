"""Virtualization syslog carry vs Terraform/Hyper-V ISO no-carry (Phase 32)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

NTP_DEC = "Dec 31 23:59:00 ntp1 ntpd[99]: synchronized to 10.0.0.1"
NTP_JAN = "Jan  1 00:00:01 ntp1 ntpd[99]: synchronized to 10.0.0.1"
KVM_DEC = "Dec 31 23:59:00 kvmhost libvirtd[1234]: Domain 'web01' started"
KVM_JAN = "Jan  1 00:00:01 kvmhost libvirtd[1234]: Domain 'web01' started"
HYPERV = (
    "TimeCreated=2024-01-15T10:00:01.000Z Provider=Microsoft-Windows-Hyper-V-VMMS "
    "Computer=HV01 Message=VM web01 started"
)
TERRAFORM = (
    "2024-01-15T10:00:03Z Apply complete! Resources: 1 added, 0 changed, 0 destroyed. "
    "user=alice host=ci01"
)


def test_ntp_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        NTP_DEC, "ntp", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        NTP_JAN, "ntp", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_kvm_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        KVM_DEC, "hypervisor", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        KVM_JAN, "hypervisor", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024
    assert first.entity_type == "host"


def test_hyperv_iso_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        HYPERV, "hypervisor", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_terraform_iso_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        TERRAFORM, "iac", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
