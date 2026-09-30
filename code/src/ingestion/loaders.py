"""Stream raw log files from ``paths.raw_log_dir``.

Encoding policy: try UTF-8 strict first; on decode failure reopen as latin-1
(with replacement). Never load an entire file into memory.

Log-source routing is content-first with filename fallback:
SSH-looking lines are tagged ``ssh`` even when the file is named generically
(e.g. ``SSH.log`` / ``server1.log``). Phase 19 also recognizes ``linux_pam``,
``linux_auth``, and ``linux_wtmp`` from content before falling back to filename.
Phase 20 recognizes Windows Event Log markers (``EventID``, ``LogName``,
``Microsoft-Windows-``, ``<Event xmlns``) after SSH and Linux auth.
Phase 21 recognizes Unix OS remainder and macOS after Windows.
Phase 22 recognizes identity sources (LDAP, RADIUS, IdP, MFA, KDC, Vault)
after Windows and before Unix syslog catch-all.
Phase 23 recognizes network infrastructure (pfSense filterlog, Cisco IOS,
OpenVPN, BIND, dhcpd, Squid, nfdump, HAProxy, ISE, hostapd, FRR bgpd)
after identity and before Unix syslog catch-all.
Phase 24 recognizes security appliances (Suricata EVE, ModSecurity JSON,
ClamAV FOUND, cowrie, Cuckoo) after network and before Unix syslog catch-all.
Phase 25 recognizes application/web (combined access, IIS W3C, error_log,
JSON runtime, Kong) after security and before Unix syslog catch-all.
Phase 26 recognizes database engines (PostgreSQL stderr, MySQL general/slow,
MSSQL errorlog, Oracle alert, Mongo JSON, Cassandra, Redis) after security
and before application JSON runtime.
Phase 27 recognizes cloud/SaaS exports (CloudTrail JSONL, VPC Flow, ALB, Azure
AD JSON, GCP Audit) after security and before database (so RDS does not become
``db_postgres`` and ALB does not become ``web_access``).
Phase 28 recognizes container/orchestration exports (Docker, K8s audit, kube
components, CRI pod stdout, Istio mesh, Helm, registry). Mesh markers run
before network so Istio ``outbound|`` does not become ``proxy``. Remaining
container sources run after cloud and before database/application.
Phase 29 recognizes email and collaboration-audit exports (Postfix smtpd/smtp
vs qmgr/pickup/cleanup, rspamd, OpenDMARC/OpenDKIM, Slack/Teams/Zoom JSON).
Email markers run after cloud so M365 UAL ``Workload`` stays ``saas_m365``,
and before Unix syslog catch-all so Postfix does not become ``linux_syslog``.
Phase 30 recognizes CI/CD and supply-chain exports (Jenkins/GHA/GitLab/CircleCI,
deploy, Nexus/Artifactory, git received-pack, npm/pip/maven, Trivy/Grype).
CI/CD markers run after email and before application so Nexus ``/repository/``
does not become ``web_access``, and after container so registry pull/push JSON
stays ``container_registry``.
Phase 31 recognizes middleware/queue exports (Kafka server/controller, RabbitMQ
connection/channel, ESB ``tx_id``/``route`` JSON, Redis/Memcached cache, Airflow).
Cache is ``cache`` only when filename is ``monitor.log`` (or cache/memcached) or
the line has a ``MONITOR`` / memcached-verbose marker; Redis server/MONITOR
output otherwise stays ``db_redis``. Airflow runs before Unix so DAG logs are
not ``linux_cron``.
Phase 32 recognizes virtualization/infrastructure exports (ESXi/Hyper-V/libvirt,
SAN LUN/volume, Veeam/Commvault/Bacula, ntpd/chronyd, FlexLM, Ansible/Puppet/Chef,
Terraform plan/apply). Terraform ``Apply complete`` is ``iac`` (not ``cicd_deploy``).
``libvirtd[`` is ``hypervisor`` (not ``docker``). ``ntpd[`` is ``ntp`` (not
``linux_syslog``).
Phase 33 recognizes physical-security / IoT / ICS exports (badge CSV/syslog,
CCTV ``camera_id`` JSON, BMS panel/alarm, IoT ``device_id``/firmware, ICS
``plc``/``tag``). Markers require ``badge``/``door``/``camera``/``plc`` (or
filename tokens) so generic syslog stays ``linux_syslog``.
Phase 34 recognizes telephony exports (Asterisk/Kamailio SIP ``INVITE``/
``REGISTER``, PBX CSV CDRs, video-conferencing ``meeting_id`` JSON, IVR
``call_id``/``menu``/``agent``). SIP markers require ``sip:`` or a SIP
program so OpenSSH ``Failed password`` stays ``ssh``. Zoom/Teams **call**
JSON is ``video_conf``; **audit** stays ``collab_audit``.
Phase 35 recognizes PKI/crypto exports (CA issued/revoked, HSM slot/op,
nginx ``ssl_handshake`` / OpenSSL ``s_server``, CT ``domain``/``issuer``,
code-signing ``hash``/``signer``). Handshake lines with ``ssl_handshake``
are ``tls`` (not ``web_access``). Vault JSON ``type=request|response`` stays
``vault``.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from src.ingestion.extractors.application.markers import (
    detect_application_log_source_from_filename,
    detect_application_log_source_from_line,
)
from src.ingestion.extractors.cloud.markers import (
    detect_cloud_log_source_from_filename,
    detect_cloud_log_source_from_line,
)
from src.ingestion.extractors.containers.markers import (
    detect_container_log_source_from_filename,
    detect_container_log_source_from_line,
    detect_service_mesh_from_line,
)
from src.ingestion.extractors.database.markers import (
    detect_database_log_source_from_filename,
    detect_database_log_source_from_line,
)
from src.ingestion.extractors.email.markers import (
    detect_email_log_source_from_filename,
    detect_email_log_source_from_line,
)
from src.ingestion.extractors.cicd.markers import (
    detect_cicd_log_source_from_filename,
    detect_cicd_log_source_from_line,
)
from src.ingestion.extractors.middleware.markers import (
    detect_middleware_log_source_from_filename,
    detect_middleware_log_source_from_line,
    is_cache_filename,
    is_redis_monitor_output,
)
from src.ingestion.extractors.virtualization.markers import (
    detect_virtualization_log_source_from_filename,
    detect_virtualization_log_source_from_line,
)
from src.ingestion.extractors.physical.markers import (
    detect_physical_log_source_from_filename,
    detect_physical_log_source_from_line,
)
from src.ingestion.extractors.telephony.markers import (
    detect_telephony_log_source_from_filename,
    detect_telephony_log_source_from_line,
    has_strong_sip_markers,
)
from src.ingestion.extractors.pki.markers import (
    detect_pki_log_source_from_filename,
    detect_pki_log_source_from_line,
)
from src.ingestion.extractors.identity.markers import (
    detect_identity_log_source_from_filename,
    detect_identity_log_source_from_line,
)
from src.ingestion.extractors.network.markers import (
    detect_network_log_source_from_filename,
    detect_network_log_source_from_line,
)
from src.ingestion.extractors.security.markers import (
    detect_security_log_source_from_filename,
    detect_security_log_source_from_line,
)
from src.ingestion.extractors.zeek.markers import (
    detect_zeek_log_source_from_filename,
    detect_zeek_log_source_from_line,
)
from src.ingestion.extractors.unix_os.markers import (
    detect_unix_os_log_source_from_filename,
    detect_unix_os_log_source_from_line,
)
from src.ingestion.extractors.windows.markers import (
    detect_windows_log_source_from_filename,
    detect_windows_log_source_from_line,
)
from src.ingestion.file_hash import hash_bytes
from src.ingestion.models import IngestedLine

logger = logging.getLogger(__name__)

SKIP_NAMES = frozenset({".gitkeep", ".DS_Store"})

# Filename hints (substring match on lowercased basename).
# LogHub ships OpenSSH as SSH.log / SSH.tar.gz contents.
_SSH_FILENAME_TOKENS = ("auth", "secure", "sshd", "ssh", "openssh")
_WTMP_FILENAME_TOKENS = ("wtmp", "btmp", "utmp")

# Strong SSH content markers (case-insensitive) — LogHub OpenSSH syslog style.
_SSH_CONTENT_MARKERS = (
    re.compile(r"sshd\[", re.IGNORECASE),
    re.compile(r"failed password for", re.IGNORECASE),
    re.compile(r"accepted (?:password|publickey|keyboard-interactive)", re.IGNORECASE),
    re.compile(r"invalid user\s+", re.IGNORECASE),
    re.compile(r"pam_unix\(sshd", re.IGNORECASE),
    re.compile(r"pam_sss\(sshd", re.IGNORECASE),
    re.compile(r"disconnected from", re.IGNORECASE),
    re.compile(r"connection closed by", re.IGNORECASE),
    re.compile(r"received disconnect from", re.IGNORECASE),
    re.compile(r"did not receive identification string", re.IGNORECASE),
    re.compile(r"possible break-in attempt", re.IGNORECASE),
    re.compile(r"maximum authentication attempts", re.IGNORECASE),
    re.compile(r"too many authentication failures", re.IGNORECASE),
    re.compile(r"user not allowed because", re.IGNORECASE),
    re.compile(r"refused connect from", re.IGNORECASE),
    re.compile(r"error: connect_to", re.IGNORECASE),
)
_SSH_SESSION = re.compile(r"session (?:opened|closed)", re.IGNORECASE)
_HAS_SSHD = re.compile(r"sshd", re.IGNORECASE)

_PAM_NON_SSHD = re.compile(r"pam_(?:unix|sss)\((?!sshd:)", re.IGNORECASE)
_SUDO_PROG = re.compile(r"\bsudo:", re.IGNORECASE)
_SU_PROG = re.compile(r"\bsu\[", re.IGNORECASE)
_LOGIN_FAIL = re.compile(r"FAILED LOGIN", re.IGNORECASE)
_AUTH_FAILURE = re.compile(r"authentication failure", re.IGNORECASE)

_UTMPDUMP = re.compile(r"^\[\d+\]\s+\[[^\]]*\]\s+\[[^\]]*\]\s+\[[^\]]*\]")
_LAST_LINE = re.compile(
    r"^\S+\s+(?:pts/\S+|tty\S+|console|:0|system)\s+",
    re.IGNORECASE,
)
_STILL_LOGGED_IN = re.compile(r"still logged in", re.IGNORECASE)


class RawLogDirError(Exception):
    """Raised when the configured raw log directory is missing or invalid."""


def detect_log_source(path: Path) -> str:
    """Guess log family from filename heuristics (fallback when content is silent)."""
    name = path.name.lower()
    if name == "pam.log" or name.endswith(".pam.log"):
        return "linux_pam"
    if name == "last.log" or name.endswith("last.log"):
        return "linux_wtmp"
    if any(token in name for token in _WTMP_FILENAME_TOKENS):
        return "linux_wtmp"
    identity = detect_identity_log_source_from_filename(path)
    if identity is not None:
        return identity
    unix = detect_unix_os_log_source_from_filename(path)
    if unix is not None:
        return unix
    windows = detect_windows_log_source_from_filename(path)
    if windows is not None:
        return windows
    network = detect_network_log_source_from_filename(path)
    if network is not None:
        return network
    security = detect_security_log_source_from_filename(path)
    if security is not None:
        return security
    zeek = detect_zeek_log_source_from_filename(path)
    if zeek is not None:
        return zeek
    cloud = detect_cloud_log_source_from_filename(path)
    if cloud is not None:
        return cloud
    container = detect_container_log_source_from_filename(path)
    if container is not None:
        return container
    email = detect_email_log_source_from_filename(path)
    if email is not None:
        return email
    cicd = detect_cicd_log_source_from_filename(path)
    if cicd is not None:
        return cicd
    middleware = detect_middleware_log_source_from_filename(path)
    if middleware is not None:
        return middleware
    virtualization = detect_virtualization_log_source_from_filename(path)
    if virtualization is not None:
        return virtualization
    physical = detect_physical_log_source_from_filename(path)
    if physical is not None:
        return physical
    telephony = detect_telephony_log_source_from_filename(path)
    if telephony is not None:
        return telephony
    pki = detect_pki_log_source_from_filename(path)
    if pki is not None:
        return pki
    application = detect_application_log_source_from_filename(path)
    if application is not None:
        return application
    database = detect_database_log_source_from_filename(path)
    if database is not None:
        return database
    if any(token in name for token in _SSH_FILENAME_TOKENS):
        return "ssh"
    return "unknown"


def detect_log_source_from_line(raw_line: str) -> str | None:
    """Return a family when the line body has strong markers; else None."""
    if not raw_line:
        return None
    if _is_ssh_line(raw_line):
        return "ssh"
    if _PAM_NON_SSHD.search(raw_line):
        return "linux_pam"
    if _is_linux_auth_line(raw_line):
        return "linux_auth"
    if _is_linux_wtmp_line(raw_line):
        return "linux_wtmp"
    windows = detect_windows_log_source_from_line(raw_line)
    if windows is not None:
        return windows
    identity = detect_identity_log_source_from_line(raw_line)
    if identity is not None:
        return identity
    mesh = detect_service_mesh_from_line(raw_line)
    if mesh is not None:
        return mesh
    network = detect_network_log_source_from_line(raw_line)
    if network is not None:
        return network
    security = detect_security_log_source_from_line(raw_line)
    if security is not None:
        return security
    zeek = detect_zeek_log_source_from_line(raw_line)
    if zeek is not None:
        return zeek
    cloud = detect_cloud_log_source_from_line(raw_line)
    if cloud is not None:
        return cloud
    container = detect_container_log_source_from_line(raw_line)
    if container is not None:
        return container
    email = detect_email_log_source_from_line(raw_line)
    if email is not None:
        return email
    cicd = detect_cicd_log_source_from_line(raw_line)
    if cicd is not None:
        return cicd
    middleware = detect_middleware_log_source_from_line(raw_line)
    if middleware is not None:
        return middleware
    virtualization = detect_virtualization_log_source_from_line(raw_line)
    if virtualization is not None:
        return virtualization
    physical = detect_physical_log_source_from_line(raw_line)
    if physical is not None:
        return physical
    telephony = detect_telephony_log_source_from_line(raw_line)
    if telephony is not None:
        return telephony
    pki = detect_pki_log_source_from_line(raw_line)
    if pki is not None:
        return pki
    database = detect_database_log_source_from_line(raw_line)
    if database is not None:
        return database
    application = detect_application_log_source_from_line(raw_line)
    if application is not None:
        return application
    unix = detect_unix_os_log_source_from_line(raw_line)
    if unix is not None:
        return unix
    return None


def _is_ssh_line(raw_line: str) -> bool:
    if has_strong_sip_markers(raw_line):
        return False
    for pattern in _SSH_CONTENT_MARKERS:
        if pattern.search(raw_line):
            return True
    if _SSH_SESSION.search(raw_line) and _HAS_SSHD.search(raw_line):
        return True
    return False


def _is_linux_auth_line(raw_line: str) -> bool:
    if _HAS_SSHD.search(raw_line):
        return False
    if _SUDO_PROG.search(raw_line) or _SU_PROG.search(raw_line):
        return True
    if _LOGIN_FAIL.search(raw_line):
        return True
    if _AUTH_FAILURE.search(raw_line):
        return True
    return False


def _is_linux_wtmp_line(raw_line: str) -> bool:
    stripped = raw_line.strip()
    if _UTMPDUMP.match(stripped):
        return True
    if _STILL_LOGGED_IN.search(stripped):
        return True
    if _LAST_LINE.match(stripped) and re.search(
        r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b", stripped
    ):
        return True
    return False


def resolve_log_source(path: Path, raw_line: str) -> str:
    """Content-first source resolution; filename is fallback.

    Redis MONITOR-output lines stay ``db_redis`` unless the filename is a
    documented cache token (``monitor.log`` / ``cache.log`` / memcached).
    """
    from_line = detect_log_source_from_line(raw_line)
    if (
        from_line == "db_redis"
        and is_cache_filename(path)
        and is_redis_monitor_output(raw_line)
    ):
        return "cache"
    if from_line is not None:
        return from_line
    return detect_log_source(path)


def iter_raw_log_paths(raw_dir: Path) -> Iterator[Path]:
    """Yield ingestible files under ``raw_dir`` in stable order."""
    for path in sorted(raw_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in SKIP_NAMES:
            continue
        yield path


def read_log_files(
    config: dict[str, Any],
    *,
    evidence_line_hash: bool = False,
    max_line_bytes: int = 1_048_576,
    on_dead_letter: Callable[[dict[str, Any]], None] | None = None,
    source_paths: Sequence[Path | str] | None = None,
) -> Iterator[IngestedLine]:
    """Walk ``raw_log_dir`` (or an explicit ``source_paths`` list) and yield lines.

    Oversized lines and unreadable files are reported via ``on_dead_letter``
    (R6) and skipped so ingest can continue.
    """
    if source_paths is not None:
        paths = [Path(p) for p in source_paths]
        for path in paths:
            if not path.is_file():
                raise RawLogDirError(f"source path is not a file: {path}")
            yield from _iter_file_lines(
                path,
                evidence_line_hash=evidence_line_hash,
                max_line_bytes=max_line_bytes,
                on_dead_letter=on_dead_letter,
            )
        return

    raw_dir = Path(config["paths"]["raw_log_dir"])
    if not raw_dir.is_dir():
        raise RawLogDirError(f"raw_log_dir not found or not a directory: {raw_dir}")

    for path in iter_raw_log_paths(raw_dir):
        yield from _iter_file_lines(
            path,
            evidence_line_hash=evidence_line_hash,
            max_line_bytes=max_line_bytes,
            on_dead_letter=on_dead_letter,
        )


def _iter_file_lines(
    path: Path,
    *,
    evidence_line_hash: bool = False,
    max_line_bytes: int = 1_048_576,
    on_dead_letter: Callable[[dict[str, Any]], None] | None = None,
) -> Iterator[IngestedLine]:
    ingested_at = datetime.now(timezone.utc)
    source_path = str(path)

    try:
        if evidence_line_hash:
            try:
                yield from _stream_binary_lines(
                    path,
                    source_path,
                    ingested_at,
                    encoding="utf-8",
                    errors="strict",
                    max_line_bytes=max_line_bytes,
                    on_dead_letter=on_dead_letter,
                )
            except UnicodeDecodeError:
                logger.warning("UTF-8 decode failed for %s; retrying as latin-1", path)
                yield from _stream_binary_lines(
                    path,
                    source_path,
                    ingested_at,
                    encoding="latin-1",
                    errors="replace",
                    max_line_bytes=max_line_bytes,
                    on_dead_letter=on_dead_letter,
                )
            return

        try:
            with path.open(encoding="utf-8", errors="strict", newline="") as handle:
                yield from _stream_handle(
                    handle,
                    source_path,
                    ingested_at,
                    max_line_bytes=max_line_bytes,
                    on_dead_letter=on_dead_letter,
                )
        except UnicodeDecodeError:
            logger.warning("UTF-8 decode failed for %s; retrying as latin-1", path)
            with path.open(encoding="latin-1", errors="replace", newline="") as handle:
                yield from _stream_handle(
                    handle,
                    source_path,
                    ingested_at,
                    max_line_bytes=max_line_bytes,
                    on_dead_letter=on_dead_letter,
                )
    except OSError as exc:
        logger.warning("skipping unreadable log file %s: %s", path, exc)
        if on_dead_letter is not None:
            on_dead_letter(
                {
                    "source_path": source_path,
                    "line_number": None,
                    "reason": "open_failed",
                    "message": str(exc),
                }
            )
            return
        raise


def _stream_binary_lines(
    path: Path,
    source_path: str,
    ingested_at: datetime,
    *,
    encoding: str,
    errors: str,
    max_line_bytes: int = 1_048_576,
    on_dead_letter: Callable[[dict[str, Any]], None] | None = None,
) -> Iterator[IngestedLine]:
    """Split on raw newlines and hash line *bytes* for evidence (R4)."""
    with path.open("rb") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line_bytes = raw.rstrip(b"\r\n")
            if not line_bytes:
                continue
            if len(line_bytes) > max_line_bytes:
                if on_dead_letter is not None:
                    on_dead_letter(
                        {
                            "source_path": source_path,
                            "line_number": line_number,
                            "reason": "line_too_long",
                            "size_bytes": len(line_bytes),
                            "snippet": line_bytes[:200].decode("latin-1", errors="replace"),
                        }
                    )
                continue
            raw_line = line_bytes.decode(encoding, errors=errors)
            yield IngestedLine(
                source_path=source_path,
                log_source=resolve_log_source(path, raw_line),
                line_number=line_number,
                raw_line=raw_line,
                content_hash=hash_raw_line(raw_line),
                ingested_at=ingested_at,
                evidence_hash=hash_bytes(line_bytes),
            )


def _stream_handle(
    handle: TextIO,
    source_path: str,
    ingested_at: datetime,
    *,
    max_line_bytes: int = 1_048_576,
    on_dead_letter: Callable[[dict[str, Any]], None] | None = None,
) -> Iterator[IngestedLine]:
    path = Path(source_path)
    for line_number, raw in enumerate(handle, start=1):
        raw_line = raw.rstrip("\r\n")
        if not raw_line:
            continue
        size_bytes = len(raw_line.encode("utf-8", errors="replace"))
        if size_bytes > max_line_bytes:
            if on_dead_letter is not None:
                on_dead_letter(
                    {
                        "source_path": source_path,
                        "line_number": line_number,
                        "reason": "line_too_long",
                        "size_bytes": size_bytes,
                        "snippet": raw_line[:200],
                    }
                )
            continue
        yield IngestedLine(
            source_path=source_path,
            log_source=resolve_log_source(path, raw_line),
            line_number=line_number,
            raw_line=raw_line,
            content_hash=hash_raw_line(raw_line),
            ingested_at=ingested_at,
        )


def hash_raw_line(raw_line: str) -> str:
    """Return sha256 hex digest of the raw line text (dedup Policy A)."""
    return hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()
