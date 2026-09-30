"""Parametrized container subtype extractors (Phase 28)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.containers import CONTAINER_LOG_SOURCES
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "containers"

_FILE_FOR_SOURCE = {
    "docker": "docker.txt",
    "k8s_audit": "k8s_audit.json",
    "k8s_apiserver": "kube-apiserver.txt",
    "k8s_kubelet": "kubelet.txt",
    "k8s_scheduler": "kube-scheduler.txt",
    "k8s_pod": "pod.txt",
    "k8s_admission": "admission.json",
    "service_mesh": "istio.txt",
    "helm": "helm.txt",
    "container_registry": "registry.json",
}


@pytest.mark.parametrize("log_source", sorted(_FILE_FOR_SOURCE))
def test_subtype_fixture_extracts(log_source: str) -> None:
    path = FIXTURE_DIR / _FILE_FOR_SOURCE[log_source]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 10
    assert resolve_log_source(path, lines[0]) == log_source
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, log_source, default_year=2024)
        if result.extraction_ok:
            ok += 1
    assert ok >= 1


def test_all_container_sources_have_fixtures() -> None:
    missing = [
        source
        for source in sorted(CONTAINER_LOG_SOURCES)
        if not (FIXTURE_DIR / _FILE_FOR_SOURCE[source]).is_file()
    ]
    assert missing == []
