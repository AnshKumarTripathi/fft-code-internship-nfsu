"""CI/CD family extractors (Phase 30)."""

from src.ingestion.extractors.cicd.artifact_repo import extract_artifact_repo
from src.ingestion.extractors.cicd.build import extract_cicd_build
from src.ingestion.extractors.cicd.deploy import extract_cicd_deploy
from src.ingestion.extractors.cicd.image_scan import extract_image_scan
from src.ingestion.extractors.cicd.package_resolve import extract_package_resolve
from src.ingestion.extractors.cicd.vcs_audit import extract_vcs_audit
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

CICD_LOG_SOURCES = frozenset(
    {
        "cicd_build",
        "cicd_deploy",
        "artifact_repo",
        "vcs_audit",
        "package_resolve",
        "image_scan",
    }
)

_EXTRACTORS = {
    "cicd_build": extract_cicd_build,
    "cicd_deploy": extract_cicd_deploy,
    "artifact_repo": extract_artifact_repo,
    "vcs_audit": extract_vcs_audit,
    "package_resolve": extract_package_resolve,
    "image_scan": extract_image_scan,
}

__all__ = [
    "CICD_LOG_SOURCES",
    "extract_cicd_family",
]


def extract_cicd_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a CI/CD ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported cicd log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
