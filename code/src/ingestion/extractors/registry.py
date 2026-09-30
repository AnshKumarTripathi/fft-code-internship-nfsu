"""Registered ingest ``log_source`` names (Phase 19+)."""

from __future__ import annotations

from src.ingestion.extractors.application import APPLICATION_LOG_SOURCES
from src.ingestion.extractors.cloud import CLOUD_LOG_SOURCES
from src.ingestion.extractors.containers import CONTAINER_LOG_SOURCES
from src.ingestion.extractors.database import DATABASE_LOG_SOURCES
from src.ingestion.extractors.email import EMAIL_LOG_SOURCES
from src.ingestion.extractors.cicd import CICD_LOG_SOURCES
from src.ingestion.extractors.identity import IDENTITY_LOG_SOURCES
from src.ingestion.extractors.middleware import MIDDLEWARE_LOG_SOURCES
from src.ingestion.extractors.network import NETWORK_LOG_SOURCES
from src.ingestion.extractors.security import SECURITY_LOG_SOURCES
from src.ingestion.extractors.unix_os import UNIX_OS_LOG_SOURCES
from src.ingestion.extractors.virtualization import VIRTUALIZATION_LOG_SOURCES
from src.ingestion.extractors.physical import PHYSICAL_LOG_SOURCES
from src.ingestion.extractors.telephony import TELEPHONY_LOG_SOURCES
from src.ingestion.extractors.pki import PKI_LOG_SOURCES
from src.ingestion.extractors.windows import WINDOWS_LOG_SOURCES
from src.ingestion.extractors.zeek import ZEEK_LOG_SOURCES

REGISTERED_LOG_SOURCES = (
    frozenset({"ssh", "linux_pam", "linux_auth", "linux_wtmp"})
    | WINDOWS_LOG_SOURCES
    | UNIX_OS_LOG_SOURCES
    | IDENTITY_LOG_SOURCES
    | NETWORK_LOG_SOURCES
    | SECURITY_LOG_SOURCES
    | ZEEK_LOG_SOURCES
    | CLOUD_LOG_SOURCES
    | CONTAINER_LOG_SOURCES
    | EMAIL_LOG_SOURCES
    | CICD_LOG_SOURCES
    | MIDDLEWARE_LOG_SOURCES
    | VIRTUALIZATION_LOG_SOURCES
    | PHYSICAL_LOG_SOURCES
    | TELEPHONY_LOG_SOURCES
    | PKI_LOG_SOURCES
    | APPLICATION_LOG_SOURCES
    | DATABASE_LOG_SOURCES
)
