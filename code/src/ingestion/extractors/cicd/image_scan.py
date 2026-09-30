"""Container image vulnerability-scan extraction (``image_scan``)."""

from __future__ import annotations

from src.ingestion.extractors.cicd.common import (
    YEAR_POLICY_CARRY,
    build_cicd_extraction_result,
    nested_str,
    parse_cicd_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_image_scan(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract image name from Trivy or Grype JSON. No syslog carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_cicd_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no image_scan JSON object",
        )
    image = str(
        obj.get("ArtifactName")
        or obj.get("Artifact")
        or nested_str(obj, "source", "target", "userInput")
        or nested_str(obj, "source", "target", "target")
        or ""
    )
    extra: dict[str, str] = {}
    if image:
        extra["image"] = image
    severity = _first_severity(obj)
    if severity:
        extra["severity"] = severity
    event_timestamp = parse_cicd_json_timestamp(obj)
    return build_cicd_extraction_result(
        service=image or "image-scan",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no image_scan entity extracted",
    )


def _first_severity(obj: dict) -> str:
    vulns = obj.get("Vulnerabilities")
    if isinstance(vulns, list) and vulns and isinstance(vulns[0], dict):
        return str(vulns[0].get("Severity") or vulns[0].get("severity") or "")
    results = obj.get("Results")
    if isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                continue
            inner = item.get("Vulnerabilities")
            if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                return str(inner[0].get("Severity") or inner[0].get("severity") or "")
    matches = obj.get("matches")
    if isinstance(matches, list) and matches and isinstance(matches[0], dict):
        vuln = matches[0].get("vulnerability")
        if isinstance(vuln, dict):
            return str(vuln.get("severity") or vuln.get("Severity") or "")
    return ""
