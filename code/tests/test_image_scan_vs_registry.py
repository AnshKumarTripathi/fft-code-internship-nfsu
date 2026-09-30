"""image_scan vs Phase 28 container_registry isolation (Phase 30)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

TRIVY = (
    '{"SchemaVersion":2,"ArtifactName":"nginx:1.25","CreatedAt":"2024-01-15T10:00:01Z",'
    '"Results":[{"Target":"nginx:1.25","Vulnerabilities":'
    '[{"VulnerabilityID":"CVE-2024-1","Severity":"HIGH"}]}]}'
)
REGISTRY = (
    '{"timestamp":"2024-01-15T10:00:01Z","action":"pull","repository":"library/nginx",'
    '"user":"alice","ip":"10.0.0.8"}'
)


def test_trivy_is_image_scan() -> None:
    assert detect_log_source_from_line(TRIVY) == "image_scan"
    assert resolve_log_source(Path("registry.json"), TRIVY) == "image_scan"
    result = extract_entity_and_timestamp(TRIVY, "image_scan", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "nginx:1.25"
    assert result.entity_type == "service"


def test_registry_pull_stays_container_registry() -> None:
    assert detect_log_source_from_line(REGISTRY) == "container_registry"
    assert resolve_log_source(Path("image_scan.json"), REGISTRY) == "container_registry"
    result = extract_entity_and_timestamp(REGISTRY, "container_registry", default_year=1999)
    assert result.extraction_ok is True
    assert result.raw_fields.get("src_ip") == "10.0.0.8"
