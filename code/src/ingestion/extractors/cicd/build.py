"""CI build-server extraction (``cicd_build``) — Jenkins, GHA, GitLab, CircleCI."""

from __future__ import annotations

from src.ingestion.extractors.cicd.common import (
    CIRCLE_STEP,
    GHA_GROUP,
    JOB_NAME,
    STARTED_BY,
    YEAR_POLICY_CARRY,
    build_cicd_extraction_result,
    json_username,
    nested_str,
    normalize_username,
    parse_cicd_json_timestamp,
    parse_json_object,
    parse_leading_iso_timestamp,
)
from src.ingestion.extractors.cicd.markers import CIRCLECI, GHA, GITLAB_RUNNER, JENKINS
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_cicd_build(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user or job from Jenkins, GHA, GitLab JSON, or CircleCI lines."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is not None:
        return _extract_gitlab_job(obj)
    if GHA.search(line):
        return _extract_gha(line)
    if CIRCLECI.search(line):
        return _extract_circleci(line)
    if GITLAB_RUNNER.search(line):
        return _extract_gitlab_text(line)
    return _extract_jenkins(line)


def _extract_gitlab_job(obj: dict) -> ExtractionResult:
    username = json_username(obj)
    job = str(obj.get("job_name") or obj.get("name") or obj.get("job") or "")
    extra = {"platform": "gitlab"}
    if job:
        extra["job"] = job
    project = str(obj.get("project") or nested_str(obj, "project", "name") or "")
    if project:
        extra["project"] = project
    event_timestamp = parse_cicd_json_timestamp(obj)
    return build_cicd_extraction_result(
        username=username,
        service=job or "gitlab-job",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cicd_build gitlab entity extracted",
    )


def _extract_gha(line: str) -> ExtractionResult:
    extra = {"platform": "gha"}
    group = GHA_GROUP.search(line)
    job = group.group("label").strip() if group else ""
    if job:
        extra["job"] = job
    actor = ""
    actor_match = STARTED_BY.search(line)
    if actor_match:
        actor = normalize_username(actor_match.group("user"))
    event_timestamp = parse_leading_iso_timestamp(line)
    return build_cicd_extraction_result(
        username=actor,
        service=job or "gha",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cicd_build gha entity extracted",
    )


def _extract_circleci(line: str) -> ExtractionResult:
    extra = {"platform": "circleci"}
    step = CIRCLE_STEP.search(line)
    job = step.group("label").strip() if step else ""
    if job:
        extra["job"] = job
    user = ""
    started = STARTED_BY.search(line)
    if started:
        user = normalize_username(started.group("user"))
    event_timestamp = parse_leading_iso_timestamp(line)
    return build_cicd_extraction_result(
        username=user,
        service=job or "circleci",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cicd_build circleci entity extracted",
    )


def _extract_gitlab_text(line: str) -> ExtractionResult:
    extra = {"platform": "gitlab"}
    job_match = JOB_NAME.search(line)
    job = ""
    if job_match:
        job = job_match.group("job") or job_match.group("job2") or ""
        extra["job"] = job
    event_timestamp = parse_leading_iso_timestamp(line)
    return build_cicd_extraction_result(
        service=job or "gitlab-runner",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cicd_build gitlab-runner entity extracted",
    )


def _extract_jenkins(line: str) -> ExtractionResult:
    extra = {"platform": "jenkins"}
    started = STARTED_BY.search(line)
    username = normalize_username(started.group("user") if started else "")
    job_match = JOB_NAME.search(line)
    job = ""
    if job_match:
        job = job_match.group("job") or job_match.group("job2") or ""
        extra["job"] = job
    if JENKINS.search(line) and not job:
        extra["job"] = "jenkins"
    event_timestamp = parse_leading_iso_timestamp(line)
    return build_cicd_extraction_result(
        username=username,
        service=job or "jenkins",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cicd_build jenkins entity extracted",
    )
