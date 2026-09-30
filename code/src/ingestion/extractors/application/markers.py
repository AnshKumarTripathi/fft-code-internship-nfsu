"""Content-first and filename routing for application and web families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object

COMBINED_ACCESS = re.compile(
    r"^\S+ \S+ \S+ \[[^\]]+\] "
    r'"[A-Z]+ \S+ HTTP/\d(?:\.\d)?" '
    r"\d{3} "
)
W3C_ACCESS = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ "
    r"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \S+"
)
NGINX_ERROR = re.compile(
    r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(?:error|warn|crit|alert|emerg)\]"
)
APACHE_ERROR = re.compile(
    r"^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}\] "
    r"\[(?:[^\]:]+:)?(?:error|warn|notice|info|debug)\]"
)
TRACEBACK = re.compile(r"Traceback \(most recent call last\):")
JAVA_EXCEPTION = re.compile(
    r"Exception in thread |^[a-z][a-z0-9_.]+\.[A-Za-z]+(?:Error|Exception)\b"
)

_BASENAME_SOURCES = {
    "access.log": "web_access",
    "access_log": "web_access",
    "apache_combined.txt": "web_access",
    "nginx_access.txt": "web_access",
    "iis_w3c.txt": "web_access",
    "iis.log": "web_access",
    "error.log": "web_error",
    "error_log": "web_error",
    "web_error.txt": "web_error",
    "app_runtime.json": "app_runtime",
    "app_runtime.txt": "app_runtime",
    "exception.log": "app_exception",
    "app_exception.txt": "app_exception",
    "kong.json": "api_gateway",
    "api_gateway.json": "api_gateway",
    "api_audit.json": "api_audit",
    "api_audit.txt": "api_audit",
    "feature_flag.json": "feature_flag",
    "feature_flag.txt": "feature_flag",
    "apm.json": "apm",
    "apm.txt": "apm",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("apache_combined", "web_access"),
    ("nginx_access", "web_access"),
    ("iis_w3c", "web_access"),
    ("access_log", "web_access"),
    ("access.log", "web_access"),
    ("error_log", "web_error"),
    ("error.log", "web_error"),
    ("web_error", "web_error"),
    ("app_runtime", "app_runtime"),
    ("app_exception", "app_exception"),
    ("exception.log", "app_exception"),
    ("api_gateway", "api_gateway"),
    ("api_audit", "api_audit"),
    ("feature_flag", "feature_flag"),
    ("kong.json", "api_gateway"),
    ("apm.json", "apm"),
)


def _is_kong(obj: dict) -> bool:
    if "latencies" not in obj:
        return False
    return "client_ip" in obj or "started_at" in obj


def _is_apm(obj: dict) -> bool:
    if "duration" not in obj:
        return False
    return "traceId" in obj or "trace_id" in obj


def _is_feature_flag(obj: dict) -> bool:
    return "flag" in obj and "action" in obj


def _is_api_audit(obj: dict) -> bool:
    if "actor" not in obj:
        return False
    return "method" in obj and "path" in obj


def _is_app_runtime(obj: dict) -> bool:
    if "level" not in obj:
        return False
    if "msg" not in obj and "message" not in obj:
        return False
    return "ts" in obj or "timestamp" in obj or "time" in obj


def detect_application_log_source_from_line(line: str) -> str | None:
    """Return an application source from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_kong(obj):
            return "api_gateway"
        if _is_apm(obj):
            return "apm"
        if _is_feature_flag(obj):
            return "feature_flag"
        if _is_api_audit(obj):
            return "api_audit"
        if _is_app_runtime(obj):
            return "app_runtime"
        return None
    stripped = line.strip()
    if COMBINED_ACCESS.match(stripped) or W3C_ACCESS.match(stripped):
        return "web_access"
    if NGINX_ERROR.match(stripped) or APACHE_ERROR.match(stripped):
        return "web_error"
    if TRACEBACK.search(stripped) or JAVA_EXCEPTION.search(stripped):
        return "app_exception"
    return None


def detect_application_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal auth.log or application.txt."""
    name = path.name.lower()
    if name in {"auth.log", "application.txt", "defender.txt", "firewall.txt"}:
        return None
    if name.startswith("u_ex") and name.endswith(".log"):
        return "web_access"
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
