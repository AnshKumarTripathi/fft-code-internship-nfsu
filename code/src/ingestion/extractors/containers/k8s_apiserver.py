"""kube-apiserver component log extraction (``k8s_apiserver``)."""

from __future__ import annotations

from src.ingestion.extractors.containers.common import extract_klog_component
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_k8s_apiserver(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host from a kube-apiserver klog/syslog line."""
    return extract_klog_component(
        line,
        component="kube-apiserver",
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
