"""Content-first and filename routing for container and orchestration families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.containers.common import CRI, ENVOY, parse_json_object

DOCKERD = re.compile(r"\bdockerd\[", re.IGNORECASE)
APISERVER = re.compile(r"\bkube-apiserver(?:\[|\s|:)", re.IGNORECASE)
KUBELET = re.compile(r"\bkubelet\[|\bkubelet\.go", re.IGNORECASE)
SCHEDULER = re.compile(r"\bkube-scheduler(?:\[|\s|:)", re.IGNORECASE)
ADMISSION_KLOG = re.compile(
    r"\badmission(?:[- ]controller)?\b.*\bwebhook\b|\bwebhook\b.*\badmission\b",
    re.IGNORECASE,
)
HELM_CMD = re.compile(
    r"\bhelm\s+(?:install|upgrade|uninstall|rollback|status|list)\b",
    re.IGNORECASE,
)
HELM_RELEASE = re.compile(
    r'Release "[^"]+" has been (?:deployed|upgraded|installed)|Happy Helming',
    re.IGNORECASE,
)
HELM_SECRET = re.compile(r"helm\.sh/release", re.IGNORECASE)
REGISTRY_V2 = re.compile(r'"(?:GET|PUT|HEAD|POST|PATCH|DELETE) /v2/')
MESH_TOKEN = re.compile(r"\b(?:outbound\||inbound\||istio|linkerd|l5d-)", re.IGNORECASE)

_BASENAME_SOURCES = {
    "docker.log": "docker",
    "docker.txt": "docker",
    "dockerd.log": "docker",
    "dockerd.txt": "docker",
    "k8s_audit.json": "k8s_audit",
    "kube-apiserver.log": "k8s_apiserver",
    "kube-apiserver.txt": "k8s_apiserver",
    "kubelet.log": "k8s_kubelet",
    "kubelet.txt": "k8s_kubelet",
    "kube-scheduler.log": "k8s_scheduler",
    "kube-scheduler.txt": "k8s_scheduler",
    "pod.log": "k8s_pod",
    "pod.txt": "k8s_pod",
    "kubectl.log": "k8s_pod",
    "admission.json": "k8s_admission",
    "istio.log": "service_mesh",
    "istio.txt": "service_mesh",
    "linkerd.log": "service_mesh",
    "helm.txt": "helm",
    "helm.log": "helm",
    "registry.json": "container_registry",
    "registry.log": "container_registry",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("k8s_audit", "k8s_audit"),
    ("kube-apiserver", "k8s_apiserver"),
    ("kube-scheduler", "k8s_scheduler"),
    ("kubelet", "k8s_kubelet"),
    ("kubectl", "k8s_pod"),
    ("admission", "k8s_admission"),
    ("istio", "service_mesh"),
    ("linkerd", "service_mesh"),
    ("dockerd", "docker"),
    ("docker.log", "docker"),
    ("docker.txt", "docker"),
    ("helm.txt", "helm"),
    ("helm.log", "helm"),
    ("registry.json", "container_registry"),
    ("pod.log", "k8s_pod"),
    ("pod.txt", "k8s_pod"),
)

_SKIP_NAMES = frozenset(
    {
        "access.log",
        "error.log",
        "audit.log",
        "auth.log",
        "squid.log",
        "squid.txt",
        "proxy.txt",
        "haproxy.log",
        "haproxy.txt",
        "syslog.log",
        "syslog.txt",
    }
)


def _is_k8s_audit(obj: dict) -> bool:
    api = str(obj.get("apiVersion") or "")
    if "audit.k8s.io" not in api:
        return False
    return "verb" in obj or "user" in obj or "sourceIPs" in obj


def _is_admission(obj: dict) -> bool:
    kind = str(obj.get("kind") or "")
    if kind == "AdmissionReview":
        return True
    api = str(obj.get("apiVersion") or "")
    return "admission.k8s.io" in api and "request" in obj


def _is_docker_json(obj: dict) -> bool:
    if "log" not in obj or "stream" not in obj or "time" not in obj:
        return False
    stream = str(obj.get("stream") or "").lower()
    return stream in {"stdout", "stderr"}


def _is_registry_json(obj: dict) -> bool:
    repo = obj.get("repository") or obj.get("repo")
    action = str(obj.get("action") or obj.get("operation") or "").lower()
    if repo and action in {"pull", "push", "delete", "mount", "head"}:
        return True
    return False


def _is_service_mesh_line(line: str) -> bool:
    stripped = line.strip()
    if ENVOY.match(stripped) and MESH_TOKEN.search(stripped):
        return True
    if MESH_TOKEN.search(stripped) and re.search(r"\b(?:GET|POST|PUT|HEAD) /", stripped):
        return True
    return False


def detect_service_mesh_from_line(line: str) -> str | None:
    """Early hook so Istio/Linkerd beats Phase 23 ``proxy``."""
    if not line:
        return None
    if _is_service_mesh_line(line):
        return "service_mesh"
    return None


def detect_container_log_source_from_line(line: str) -> str | None:
    """Return a container ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    mesh = detect_service_mesh_from_line(line)
    if mesh is not None:
        return mesh
    obj = parse_json_object(line)
    if obj is not None:
        if _is_k8s_audit(obj):
            return "k8s_audit"
        if _is_admission(obj):
            return "k8s_admission"
        if _is_docker_json(obj):
            return "docker"
        if _is_registry_json(obj):
            return "container_registry"
        return None
    stripped = line.strip()
    if DOCKERD.search(stripped):
        return "docker"
    if APISERVER.search(stripped):
        return "k8s_apiserver"
    if SCHEDULER.search(stripped):
        return "k8s_scheduler"
    if KUBELET.search(stripped):
        return "k8s_kubelet"
    if CRI.match(stripped):
        return "k8s_pod"
    if ADMISSION_KLOG.search(stripped):
        return "k8s_admission"
    if HELM_CMD.search(stripped) or HELM_RELEASE.search(stripped) or HELM_SECRET.search(stripped):
        return "helm"
    if REGISTRY_V2.search(stripped):
        return "container_registry"
    return None


def detect_container_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal access.log, audit.log, or syslog."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
