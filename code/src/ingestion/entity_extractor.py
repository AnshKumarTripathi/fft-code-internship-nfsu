"""Source-specific entity and timestamp extraction.

Syslog timestamps often omit the year. Default policy is ``carry`` (Dec→Jan
increments the year while walking a file). ``file_mtime`` keeps the v1
single-year stamp.

LogHub OpenSSH (``SSH.log``) uses classic syslog lines, e.g.
``Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user X from Y``.
Masked probe usernames like ``*****`` are remapped to ``src_ip`` as the entity.
Hostname is stored in ``raw_fields`` when the syslog host token sits before
``sshd[``.

Phase 19 adds ``linux_pam``, ``linux_auth``, and ``linux_wtmp``. Phase 20 adds
``windows_*`` Event Log families. Phase 21 adds Unix OS remainder and macOS.
Phase 22 adds identity sources (LDAP, RADIUS, IdP, MFA, MIT KDC, Vault).
Phase 23 adds network infrastructure (firewall, VPN, DNS, DHCP, and siblings).
Phase 24 adds security appliances (Suricata EVE, WAF, DLP, EDR, ClamAV, and siblings).
Phase 25 adds application and web logs (Apache/Nginx/IIS access, error, JSON runtime, Kong).
Phase 26 adds database engines (PostgreSQL, MySQL, MSSQL, Oracle, MongoDB, Cassandra, Redis)
with ``raw_fields.event_class``.
Phase 27 adds cloud and SaaS audit exports (CloudTrail, VPC Flow, Azure AD, GCP Audit, M365).
Phase 28 adds container/orchestration file exports (Docker, K8s audit, kube components, pod stdout, mesh, Helm, registry).
Phase 29 adds email and collaboration-audit exports (SMTP, mail gateway, MTA, DKIM/SPF/DMARC, Slack/Teams/Zoom audit).
Phase 30 adds CI/CD and supply-chain exports (Jenkins/GHA/GitLab/CircleCI, deploy, artifact repo, VCS audit, package resolve, image scan).
Phase 31 adds middleware and queue exports (Kafka, RabbitMQ, ESB, Redis/Memcached cache, Airflow).
Phase 32 adds virtualization and infrastructure exports (hypervisor, SAN, backup, NTP, license, config_mgmt, Terraform iac).
Phase 33 adds physical-security / IoT / ICS exports (badge, CCTV, BMS, IoT firmware, ICS/SCADA).
Phase 34 adds telephony exports (VoIP/SIP, PBX CDRs, video-conferencing call logs, IVR).
Phase 35 adds PKI/crypto exports (CA issuance/revocation, HSM, TLS handshake, CT, code-signing).
An optional ``enabled_sources`` allowlist disables families at the dispatcher
(empty means all registered sources). Windows extractors ignore syslog
year-carry; Unix, identity, and network syslog-shaped lines still apply it.
"""

from __future__ import annotations

from collections.abc import Sequence

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
from src.ingestion.extractors.security import SECURITY_LOG_SOURCES, extract_security_family
from src.ingestion.extractors.ssh import extract_ssh
from src.ingestion.extractors.unix_os import UNIX_OS_LOG_SOURCES, extract_unix_os_family
from src.ingestion.extractors.zeek import ZEEK_LOG_SOURCES, extract_zeek_family
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
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_LINUX_AUTH_SOURCES = frozenset({"linux_pam", "linux_auth", "linux_wtmp"})


def extract_entity_and_timestamp(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
    enabled_sources: Sequence[str] | None = None,
) -> ExtractionResult:
    """Extract candidate entity_id, entity_type, and event_timestamp.

    Username as user if present and not masked; else src_ip as ip; else
    syslog hostname as host. ``enabled_sources`` None or empty allows every
    registered family.
    """
    if enabled_sources and log_source not in enabled_sources:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"source disabled: {log_source}",
        )
    if log_source == "ssh":
        return extract_ssh(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in _LINUX_AUTH_SOURCES:
        return extract_linux_auth_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in WINDOWS_LOG_SOURCES:
        return extract_windows_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in UNIX_OS_LOG_SOURCES:
        return extract_unix_os_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in IDENTITY_LOG_SOURCES:
        return extract_identity_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in NETWORK_LOG_SOURCES:
        return extract_network_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in SECURITY_LOG_SOURCES:
        return extract_security_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in ZEEK_LOG_SOURCES:
        return extract_zeek_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in CLOUD_LOG_SOURCES:
        return extract_cloud_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in CONTAINER_LOG_SOURCES:
        return extract_container_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in EMAIL_LOG_SOURCES:
        return extract_email_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in CICD_LOG_SOURCES:
        return extract_cicd_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in MIDDLEWARE_LOG_SOURCES:
        return extract_middleware_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in VIRTUALIZATION_LOG_SOURCES:
        return extract_virtualization_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in PHYSICAL_LOG_SOURCES:
        return extract_physical_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in TELEPHONY_LOG_SOURCES:
        return extract_telephony_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in PKI_LOG_SOURCES:
        return extract_pki_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in APPLICATION_LOG_SOURCES:
        return extract_application_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if log_source in DATABASE_LOG_SOURCES:
        return extract_database_family(
            line,
            log_source,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    return ExtractionResult(
        extraction_ok=False,
        failure_reason=f"unsupported log_source: {log_source}",
    )
