"""Cloud family extractors (Phase 27)."""

from src.ingestion.extractors.cloud.aws_cloudtrail import extract_aws_cloudtrail
from src.ingestion.extractors.cloud.aws_config import extract_aws_config
from src.ingestion.extractors.cloud.aws_elb import extract_aws_elb
from src.ingestion.extractors.cloud.aws_guardduty import extract_aws_guardduty
from src.ingestion.extractors.cloud.aws_lambda import extract_aws_lambda
from src.ingestion.extractors.cloud.aws_rds import extract_aws_rds
from src.ingestion.extractors.cloud.aws_s3 import extract_aws_s3
from src.ingestion.extractors.cloud.aws_vpcflow import extract_aws_vpcflow
from src.ingestion.extractors.cloud.azure_activity import extract_azure_activity
from src.ingestion.extractors.cloud.azure_ad import extract_azure_ad
from src.ingestion.extractors.cloud.azure_keyvault import extract_azure_keyvault
from src.ingestion.extractors.cloud.azure_monitor import extract_azure_monitor
from src.ingestion.extractors.cloud.azure_nsg import extract_azure_nsg
from src.ingestion.extractors.cloud.casb import extract_casb
from src.ingestion.extractors.cloud.gcp_audit import extract_gcp_audit
from src.ingestion.extractors.cloud.gcp_iam import extract_gcp_iam
from src.ingestion.extractors.cloud.gcp_lb import extract_gcp_lb
from src.ingestion.extractors.cloud.gcp_vpcflow import extract_gcp_vpcflow
from src.ingestion.extractors.cloud.saas_m365 import extract_saas_m365
from src.ingestion.extractors.cloud.saas_salesforce import extract_saas_salesforce
from src.ingestion.extractors.cloud.saas_workspace import extract_saas_workspace
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

CLOUD_LOG_SOURCES = frozenset(
    {
        "aws_cloudtrail",
        "aws_vpcflow",
        "aws_s3",
        "aws_elb",
        "aws_guardduty",
        "aws_config",
        "aws_lambda",
        "aws_rds",
        "azure_activity",
        "azure_ad",
        "azure_nsg",
        "azure_monitor",
        "azure_keyvault",
        "gcp_audit",
        "gcp_vpcflow",
        "gcp_lb",
        "gcp_iam",
        "casb",
        "saas_workspace",
        "saas_m365",
        "saas_salesforce",
    }
)

_EXTRACTORS = {
    "aws_cloudtrail": extract_aws_cloudtrail,
    "aws_vpcflow": extract_aws_vpcflow,
    "aws_s3": extract_aws_s3,
    "aws_elb": extract_aws_elb,
    "aws_guardduty": extract_aws_guardduty,
    "aws_config": extract_aws_config,
    "aws_lambda": extract_aws_lambda,
    "aws_rds": extract_aws_rds,
    "azure_activity": extract_azure_activity,
    "azure_ad": extract_azure_ad,
    "azure_nsg": extract_azure_nsg,
    "azure_monitor": extract_azure_monitor,
    "azure_keyvault": extract_azure_keyvault,
    "gcp_audit": extract_gcp_audit,
    "gcp_vpcflow": extract_gcp_vpcflow,
    "gcp_lb": extract_gcp_lb,
    "gcp_iam": extract_gcp_iam,
    "casb": extract_casb,
    "saas_workspace": extract_saas_workspace,
    "saas_m365": extract_saas_m365,
    "saas_salesforce": extract_saas_salesforce,
}

__all__ = [
    "CLOUD_LOG_SOURCES",
    "extract_cloud_family",
]


def extract_cloud_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a cloud ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported cloud log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
