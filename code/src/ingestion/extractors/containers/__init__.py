"""Container family extractors (Phase 28)."""

from src.ingestion.extractors.containers.docker import extract_docker
from src.ingestion.extractors.containers.helm import extract_helm
from src.ingestion.extractors.containers.k8s_admission import extract_k8s_admission
from src.ingestion.extractors.containers.k8s_apiserver import extract_k8s_apiserver
from src.ingestion.extractors.containers.k8s_audit import extract_k8s_audit
from src.ingestion.extractors.containers.k8s_kubelet import extract_k8s_kubelet
from src.ingestion.extractors.containers.k8s_pod import extract_k8s_pod
from src.ingestion.extractors.containers.k8s_scheduler import extract_k8s_scheduler
from src.ingestion.extractors.containers.registry import extract_container_registry
from src.ingestion.extractors.containers.service_mesh import extract_service_mesh
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

CONTAINER_LOG_SOURCES = frozenset(
    {
        "docker",
        "k8s_audit",
        "k8s_apiserver",
        "k8s_kubelet",
        "k8s_scheduler",
        "k8s_pod",
        "k8s_admission",
        "service_mesh",
        "helm",
        "container_registry",
    }
)

_EXTRACTORS = {
    "docker": extract_docker,
    "k8s_audit": extract_k8s_audit,
    "k8s_apiserver": extract_k8s_apiserver,
    "k8s_kubelet": extract_k8s_kubelet,
    "k8s_scheduler": extract_k8s_scheduler,
    "k8s_pod": extract_k8s_pod,
    "k8s_admission": extract_k8s_admission,
    "service_mesh": extract_service_mesh,
    "helm": extract_helm,
    "container_registry": extract_container_registry,
}

__all__ = [
    "CONTAINER_LOG_SOURCES",
    "extract_container_family",
]


def extract_container_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a container ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported container log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
