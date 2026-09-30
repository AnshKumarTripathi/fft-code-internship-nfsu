"""Cloud/container timestamps do not mutate syslog year-carry state (Phase 28)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

AUDIT = (
    '{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get",'
    '"user":{"username":"alice"},"sourceIPs":["10.0.0.8"],'
    '"requestReceivedTimestamp":"2024-01-15T10:00:01Z"}'
)
CRI = "2024-01-15T10:00:01.123456789Z stdout F starting nginx"
KLOG = "I0115 10:00:01.123456       1 kubelet.go:102] SyncLoop (ADD, \"pod\")"


def test_k8s_audit_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        AUDIT, "k8s_audit", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_cri_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        CRI, "k8s_pod", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_bare_klog_uses_default_year_without_carry() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        KLOG, "k8s_kubelet", default_year=2024, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
