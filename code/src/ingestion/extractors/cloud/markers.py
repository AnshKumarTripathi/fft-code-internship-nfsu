"""Content-first and filename routing for cloud and SaaS families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.cloud.common import parse_json_object, unwrap_json_record
from src.ingestion.extractors.identity.common import nested_str

VPCFLOW = re.compile(r"^\d+\s+\d+\s+eni-[0-9a-f]+\s+", re.IGNORECASE)
S3_REST = re.compile(r"\bREST\.(?:GET|PUT|HEAD|POST|DELETE)\.[A-Z.]+")
S3_BRACKET = re.compile(
    r"\[\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} "
)
ALB = re.compile(
    r"^(?:h2|http|https|grpcs|wss)\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*\s+app/",
    re.IGNORECASE,
)
LAMBDA_CW = re.compile(r"^(?:START|END|REPORT)\s+RequestId:", re.IGNORECASE)
RDS_PREFIX = re.compile(
    r"UTC:\d{1,3}(?:\.\d{1,3}){3}\(\d+\):[^:]+:\[\d+\]:",
)

_BASENAME_SOURCES = {
    "cloudtrail.json": "aws_cloudtrail",
    "cloudtrail.txt": "aws_cloudtrail",
    "vpcflow.txt": "aws_vpcflow",
    "vpcflow.log": "aws_vpcflow",
    "s3.txt": "aws_s3",
    "s3.log": "aws_s3",
    "alb.txt": "aws_elb",
    "alb.log": "aws_elb",
    "aws_elb.txt": "aws_elb",
    "guardduty.json": "aws_guardduty",
    "aws_config.json": "aws_config",
    "lambda.txt": "aws_lambda",
    "lambda.log": "aws_lambda",
    "rds.txt": "aws_rds",
    "rds.log": "aws_rds",
    "azure_activity.json": "azure_activity",
    "azure_ad.json": "azure_ad",
    "signins.json": "azure_ad",
    "nsg.json": "azure_nsg",
    "nsg.txt": "azure_nsg",
    "monitor.json": "azure_monitor",
    "keyvault.json": "azure_keyvault",
    "gcp_audit.json": "gcp_audit",
    "gcp_iam.json": "gcp_iam",
    "gcp_vpcflow.json": "gcp_vpcflow",
    "gcp_lb.json": "gcp_lb",
    "casb.json": "casb",
    "workspace.json": "saas_workspace",
    "m365.json": "saas_m365",
    "salesforce.json": "saas_salesforce",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("cloudtrail", "aws_cloudtrail"),
    ("vpcflow", "aws_vpcflow"),
    ("guardduty", "aws_guardduty"),
    ("aws_config", "aws_config"),
    ("azure_activity", "azure_activity"),
    ("azure_ad", "azure_ad"),
    ("signins", "azure_ad"),
    ("keyvault", "azure_keyvault"),
    ("gcp_audit", "gcp_audit"),
    ("gcp_iam", "gcp_iam"),
    ("gcp_vpcflow", "gcp_vpcflow"),
    ("gcp_lb", "gcp_lb"),
    ("workspace.json", "saas_workspace"),
    ("m365.json", "saas_m365"),
    ("salesforce.json", "saas_salesforce"),
    ("casb.json", "casb"),
    ("alb.log", "aws_elb"),
    ("alb.txt", "aws_elb"),
    ("aws_elb", "aws_elb"),
    ("lambda.log", "aws_lambda"),
    ("lambda.txt", "aws_lambda"),
    ("rds.log", "aws_rds"),
    ("rds.txt", "aws_rds"),
    ("s3.log", "aws_s3"),
    ("s3.txt", "aws_s3"),
    ("nsg.json", "azure_nsg"),
    ("monitor.json", "azure_monitor"),
)

_SKIP_NAMES = frozenset(
    {
        "haproxy.log",
        "haproxy.txt",
        "load_balancer.txt",
        "postgres.log",
        "postgresql.log",
        "postgres.txt",
        "auth.log",
        "access.log",
        "error.log",
        "app_runtime.json",
        "okta.json",
        "idp.txt",
    }
)


def _resource_type(obj: dict) -> str:
    resource = obj.get("resource")
    if isinstance(resource, dict):
        return str(resource.get("type") or "")
    return ""


def _is_gcp_iam(obj: dict) -> bool:
    method = nested_str(obj, "protoPayload", "methodName")
    return "setiampolicy" in method.lower()


def _is_gcp_audit(obj: dict) -> bool:
    atype = nested_str(obj, "protoPayload", "@type")
    if "cloudaudit.googleapis.com" in atype:
        return True
    log_name = str(obj.get("logName") or "")
    return "cloudaudit.googleapis.com" in log_name


def _is_gcp_lb(obj: dict) -> bool:
    if "httpRequest" not in obj:
        return False
    return _resource_type(obj) == "http_load_balancer" or "httpRequest" in obj and (
        "remoteIp" in (obj.get("httpRequest") or {})
        if isinstance(obj.get("httpRequest"), dict)
        else False
    )


def _is_gcp_vpcflow(obj: dict) -> bool:
    payload = obj.get("jsonPayload")
    if not isinstance(payload, dict):
        return False
    connection = payload.get("connection")
    if isinstance(connection, dict) and ("src_ip" in connection or "dest_ip" in connection):
        return True
    return "reporter" in payload and "bytes_sent" in payload


def _is_guardduty(obj: dict) -> bool:
    arn = str(obj.get("arn") or "")
    if "arn:aws:guardduty" in arn:
        return True
    service = obj.get("service")
    if isinstance(service, dict) and str(service.get("serviceName") or "").lower() == "guardduty":
        return True
    kind = str(obj.get("type") or "")
    return ":" in kind and "accountId" in obj and "schemaVersion" in obj


def _is_config(obj: dict) -> bool:
    if "configurationItemCaptureTime" in obj:
        return True
    item = obj.get("configurationItem")
    return isinstance(item, dict) and (
        "resourceType" in item or "resourceId" in item or "ARN" in item or "arn" in item
    )


def _is_cloudtrail(obj: dict) -> bool:
    record = unwrap_json_record(obj) or obj
    if "eventSource" not in record or "eventName" not in record:
        return False
    return "userIdentity" in record or "sourceIPAddress" in record or "eventTime" in record


def _is_azure_ad(obj: dict) -> bool:
    category = str(obj.get("category") or "")
    if category in {"SignInLogs", "AuditLogs", "SignInLogs", "AuditLogs"}:
        return True
    lowered = category.lower()
    if lowered in {"signinlogs", "auditlogs"}:
        return True
    props = obj.get("properties")
    if isinstance(props, dict) and "userPrincipalName" in props and "ipAddress" in props:
        return True
    return "userPrincipalName" in obj and ("ipAddress" in obj or "status" in obj)


def _is_azure_keyvault(obj: dict) -> bool:
    category = str(obj.get("category") or "")
    if category.lower() in {"auditevent", "azurekeyvault"}:
        return True
    if "callerIpAddress" in obj and "microsoft.keyvault" in str(obj.get("resourceId") or "").lower():
        return True
    return False


def _is_azure_nsg(obj: dict) -> bool:
    if "flowTuples" in obj:
        return True
    props = obj.get("properties")
    if isinstance(props, dict) and "flows" in props:
        return True
    records = obj.get("records")
    if isinstance(records, list) and records and isinstance(records[0], dict):
        if "flowTuples" in records[0]:
            return True
    category = str(obj.get("category") or "")
    return "nsgflow" in category.lower() or category == "NetworkSecurityGroupFlowEvent"


def _is_azure_activity(obj: dict) -> bool:
    if "operationName" not in obj:
        return False
    resource = str(obj.get("resourceId") or "")
    if "/providers/microsoft." not in resource.lower():
        return False
    return "caller" in obj or "identity" in obj or str(obj.get("category") or "") == "Administrative"


def _is_azure_monitor(obj: dict) -> bool:
    if "resourceId" not in obj:
        return False
    if "time" not in obj and "timestamp" not in obj:
        return False
    return "category" in obj or "resultType" in obj


def _is_workspace(obj: dict) -> bool:
    kind = str(obj.get("kind") or "")
    if kind.startswith("admin#"):
        return True
    ident = obj.get("id")
    if isinstance(ident, dict) and "applicationName" in ident:
        return True
    return False


def _is_m365(obj: dict) -> bool:
    return "Workload" in obj and "Operation" in obj and "UserId" in obj


def _is_salesforce(obj: dict) -> bool:
    return "EVENT_TYPE" in obj and ("USER_ID_DERIVED" in obj or "USER_ID" in obj)


def _is_casb(obj: dict) -> bool:
    if "flag" in obj:
        return False
    if "policy" in obj:
        return False
    if "app" not in obj or "action" not in obj:
        return False
    return "user" in obj or "username" in obj or "actor" in obj


def detect_cloud_log_source_from_line(line: str) -> str | None:
    """Return a cloud ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_gcp_iam(obj):
            return "gcp_iam"
        if _is_gcp_audit(obj):
            return "gcp_audit"
        if _is_gcp_lb(obj):
            return "gcp_lb"
        if _is_gcp_vpcflow(obj):
            return "gcp_vpcflow"
        if _is_guardduty(obj):
            return "aws_guardduty"
        if _is_config(obj):
            return "aws_config"
        if _is_cloudtrail(obj):
            return "aws_cloudtrail"
        if _is_azure_ad(obj):
            return "azure_ad"
        if _is_azure_keyvault(obj):
            return "azure_keyvault"
        if _is_azure_nsg(obj):
            return "azure_nsg"
        if _is_azure_activity(obj):
            return "azure_activity"
        if _is_azure_monitor(obj):
            return "azure_monitor"
        if _is_m365(obj):
            return "saas_m365"
        if _is_workspace(obj):
            return "saas_workspace"
        if _is_salesforce(obj):
            return "saas_salesforce"
        if _is_casb(obj):
            return "casb"
        return None
    stripped = line.strip()
    if VPCFLOW.match(stripped):
        return "aws_vpcflow"
    if ALB.match(stripped):
        return "aws_elb"
    if S3_REST.search(stripped) and S3_BRACKET.search(stripped):
        return "aws_s3"
    if LAMBDA_CW.match(stripped):
        return "aws_lambda"
    if RDS_PREFIX.search(stripped):
        return "aws_rds"
    return None


def detect_cloud_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal HAProxy, Postgres, or auth.log."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
