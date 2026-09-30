"""CI/CD JSON no-carry vs vcs_audit syslog year-carry (Phase 30)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

GITLAB = (
    '{"job_id":101,"pipeline_id":10,"project":"app","user":"alice",'
    '"job_name":"test","ts":"2024-01-15T10:00:01Z"}'
)
TRIVY = (
    '{"SchemaVersion":2,"ArtifactName":"nginx:1.25","CreatedAt":"2024-01-15T10:00:01Z",'
    '"Results":[{"Target":"nginx:1.25","Vulnerabilities":'
    '[{"VulnerabilityID":"CVE-2024-1","Severity":"HIGH"}]}]}'
)
VCS_DEC = (
    "Dec 31 23:59:00 gitserver git-shell[99]: user alice received-pack 'app.git' "
    "from 10.0.0.8"
)
VCS_JAN = (
    "Jan  1 00:00:01 gitserver git-shell[99]: user bob received-pack 'app.git' "
    "from 10.0.0.9"
)


def test_gitlab_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        GITLAB, "cicd_build", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_trivy_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        TRIVY, "image_scan", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_vcs_audit_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        VCS_DEC, "vcs_audit", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        VCS_JAN, "vcs_audit", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024
    assert first.entity_id == "alice"
    assert first.entity_type == "user"
