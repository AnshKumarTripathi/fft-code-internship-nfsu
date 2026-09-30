"""SSH extractor package plus Linux auth, Windows, Unix OS, identity, network, security, cloud, container, email, CI/CD, middleware, virtualization, physical, telephony, PKI, application, and database families."""

from src.ingestion.extractors.application import (
    APPLICATION_LOG_SOURCES,
    extract_application_family,
)
from src.ingestion.extractors.cloud import CLOUD_LOG_SOURCES, extract_cloud_family
from src.ingestion.extractors.containers import CONTAINER_LOG_SOURCES, extract_container_family
from src.ingestion.extractors.database import DATABASE_LOG_SOURCES, extract_database_family
from src.ingestion.extractors.email import EMAIL_LOG_SOURCES, extract_email_family
from src.ingestion.extractors.cicd import CICD_LOG_SOURCES, extract_cicd_family
from src.ingestion.extractors.identity import IDENTITY_LOG_SOURCES, extract_identity_family
from src.ingestion.extractors.middleware import (
    MIDDLEWARE_LOG_SOURCES,
    extract_middleware_family,
)
from src.ingestion.extractors.linux_auth import extract_linux_auth_family
from src.ingestion.extractors.network import NETWORK_LOG_SOURCES, extract_network_family
from src.ingestion.extractors.registry import REGISTERED_LOG_SOURCES
from src.ingestion.extractors.security import SECURITY_LOG_SOURCES, extract_security_family
from src.ingestion.extractors.ssh import extract_ssh
from src.ingestion.extractors.unix_os import UNIX_OS_LOG_SOURCES, extract_unix_os_family
from src.ingestion.extractors.virtualization import (
    VIRTUALIZATION_LOG_SOURCES,
    extract_virtualization_family,
)
from src.ingestion.extractors.physical import (
    PHYSICAL_LOG_SOURCES,
    extract_physical_family,
)
from src.ingestion.extractors.telephony import (
    TELEPHONY_LOG_SOURCES,
    extract_telephony_family,
)
from src.ingestion.extractors.pki import (
    PKI_LOG_SOURCES,
    extract_pki_family,
)
from src.ingestion.extractors.windows import WINDOWS_LOG_SOURCES, extract_windows_family

__all__ = [
    "APPLICATION_LOG_SOURCES",
    "CLOUD_LOG_SOURCES",
    "CONTAINER_LOG_SOURCES",
    "DATABASE_LOG_SOURCES",
    "EMAIL_LOG_SOURCES",
    "CICD_LOG_SOURCES",
    "IDENTITY_LOG_SOURCES",
    "MIDDLEWARE_LOG_SOURCES",
    "NETWORK_LOG_SOURCES",
    "REGISTERED_LOG_SOURCES",
    "SECURITY_LOG_SOURCES",
    "UNIX_OS_LOG_SOURCES",
    "VIRTUALIZATION_LOG_SOURCES",
    "PHYSICAL_LOG_SOURCES",
    "TELEPHONY_LOG_SOURCES",
    "PKI_LOG_SOURCES",
    "WINDOWS_LOG_SOURCES",
    "extract_application_family",
    "extract_cloud_family",
    "extract_container_family",
    "extract_database_family",
    "extract_email_family",
    "extract_cicd_family",
    "extract_identity_family",
    "extract_middleware_family",
    "extract_linux_auth_family",
    "extract_network_family",
    "extract_security_family",
    "extract_ssh",
    "extract_unix_os_family",
    "extract_virtualization_family",
    "extract_physical_family",
    "extract_telephony_family",
    "extract_pki_family",
    "extract_windows_family",
]
