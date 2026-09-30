"""Content-first and filename routing for CI/CD and supply-chain families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.cicd.common import parse_json_object

DEPLOY_EVENTS = frozenset({"deploy", "release", "rollback"})
VCS_ACTIONS = frozenset(
    {
        "git-receive-pack",
        "git-upload-pack",
        "received-pack",
        "repository_git_operation",
        "repo.git_push",
        "git.push",
        "push",
        "clone",
        "fetch",
        "permission_change",
        "repo_create",
    }
)

JENKINS = re.compile(
    r"Started by user|\[Pipeline\]|\bJenkins\b|Finished: (?:SUCCESS|FAILURE|ABORTED|UNSTABLE)",
    re.IGNORECASE,
)
GHA = re.compile(r"##\[(?:group|error|warning|notice)\]|\bGitHub Actions\b")
CIRCLECI = re.compile(r"\bCircleCI\b|====>>", re.IGNORECASE)
GITLAB_RUNNER = re.compile(r"\bgitlab-runner\b|Running with gitlab-runner", re.IGNORECASE)
ARTIFACT_PATH = re.compile(r"/artifactory/|/repository/", re.IGNORECASE)
ARTIFACT_PRODUCT = re.compile(r"\bnexus\b|\bartifactory\b", re.IGNORECASE)
VCS_PACK = re.compile(
    r"\breceived-pack\b|\bgit-receive-pack\b|\bgit-upload-pack\b",
    re.IGNORECASE,
)
NPM = re.compile(r"\bnpm http fetch\b|\bnpm notice\b", re.IGNORECASE)
PIP = re.compile(r"\bpip install\b|^Collecting \S+", re.IGNORECASE)
MAVEN = re.compile(r"\[INFO\] Downloading from", re.IGNORECASE)
DEPLOY_TEXT = re.compile(
    r"\bDeploying\b|\brelease published\b|\bStarted deploying\b",
    re.IGNORECASE,
)

_BASENAME_SOURCES = {
    "jenkins.txt": "cicd_build",
    "jenkins.log": "cicd_build",
    "gha.txt": "cicd_build",
    "gha.log": "cicd_build",
    "gitlab.json": "cicd_build",
    "circleci.txt": "cicd_build",
    "circleci.log": "cicd_build",
    "deploy.json": "cicd_deploy",
    "deploy.txt": "cicd_deploy",
    "artifact_repo.txt": "artifact_repo",
    "nexus.txt": "artifact_repo",
    "artifactory.txt": "artifact_repo",
    "vcs_audit.txt": "vcs_audit",
    "vcs_audit.json": "vcs_audit",
    "gitea.json": "vcs_audit",
    "package_resolve.txt": "package_resolve",
    "npm.txt": "package_resolve",
    "pip.txt": "package_resolve",
    "maven.txt": "package_resolve",
    "trivy.json": "image_scan",
    "grype.json": "image_scan",
    "image_scan.json": "image_scan",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("jenkins", "cicd_build"),
    ("circleci", "cicd_build"),
    ("gitlab.json", "cicd_build"),
    ("gha.txt", "cicd_build"),
    ("gha.log", "cicd_build"),
    ("artifact_repo", "artifact_repo"),
    ("artifactory", "artifact_repo"),
    ("nexus.txt", "artifact_repo"),
    ("vcs_audit", "vcs_audit"),
    ("gitea.json", "vcs_audit"),
    ("package_resolve", "package_resolve"),
    ("image_scan", "image_scan"),
    ("trivy.json", "image_scan"),
    ("grype.json", "image_scan"),
    ("deploy.json", "cicd_deploy"),
    ("deploy.txt", "cicd_deploy"),
)

_SKIP_NAMES = frozenset(
    {
        "access.log",
        "audit.log",
        "syslog.log",
        "syslog.txt",
        "docker.log",
        "registry.json",
        "auth.log",
    }
)


def _is_image_scan(obj: dict) -> bool:
    vulns = obj.get("Vulnerabilities")
    if isinstance(vulns, list):
        return True
    results = obj.get("Results")
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict) and isinstance(item.get("Vulnerabilities"), list):
                return True
    matches = obj.get("matches")
    if isinstance(matches, list) and matches:
        first = matches[0]
        if isinstance(first, dict) and "vulnerability" in first:
            return True
    return False


def _is_gitlab_job(obj: dict) -> bool:
    if "job_id" not in obj and "build_id" not in obj:
        return False
    return "runner" in obj or "pipeline_id" in obj or "project" in obj


def _is_deploy(obj: dict) -> bool:
    event = str(obj.get("event") or obj.get("action") or "").strip().lower()
    if event not in DEPLOY_EVENTS:
        return False
    return "service" in obj or "app" in obj or "environment" in obj


def _is_vcs_audit(obj: dict) -> bool:
    if not str(obj.get("author") or obj.get("author_name") or "").strip():
        return False
    action = str(obj.get("action") or "").strip().lower()
    if action in VCS_ACTIONS:
        return True
    return "repo" in obj or "repository" in obj or "entity_type" in obj


def detect_cicd_log_source_from_line(line: str) -> str | None:
    """Return a CI/CD ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_image_scan(obj):
            return "image_scan"
        if _is_gitlab_job(obj):
            return "cicd_build"
        if _is_deploy(obj):
            return "cicd_deploy"
        if _is_vcs_audit(obj):
            return "vcs_audit"
        return None
    stripped = line.strip()
    if JENKINS.search(stripped) or GHA.search(stripped) or CIRCLECI.search(stripped):
        return "cicd_build"
    if GITLAB_RUNNER.search(stripped):
        return "cicd_build"
    if ARTIFACT_PATH.search(stripped) or ARTIFACT_PRODUCT.search(stripped):
        return "artifact_repo"
    if VCS_PACK.search(stripped):
        return "vcs_audit"
    if NPM.search(stripped) or PIP.search(stripped) or MAVEN.search(stripped):
        return "package_resolve"
    if DEPLOY_TEXT.search(stripped):
        return "cicd_deploy"
    return None


def detect_cicd_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal access.log, audit.log, or registry.json."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
