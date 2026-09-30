"""k8s_audit extractor tests (Phase 28)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

USER = (
    '{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get",'
    '"requestURI":"/api/v1/namespaces/default/pods",'
    '"user":{"username":"alice","groups":["system:authenticated"]},'
    '"sourceIPs":["10.0.0.8"],'
    '"requestReceivedTimestamp":"2024-01-15T10:00:01Z"}'
)
SA = (
    '{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"list",'
    '"user":{"username":"system:serviceaccount:kube-system:coredns",'
    '"groups":["system:serviceaccounts"]},'
    '"sourceIPs":["10.0.0.11"],'
    '"requestReceivedTimestamp":"2024-01-15T10:00:02Z"}'
)


def test_k8s_audit_extracts_user_and_src_ip() -> None:
    assert resolve_log_source(Path("server1.log"), USER) == "k8s_audit"
    result = extract_entity_and_timestamp(USER, "k8s_audit", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "10.0.0.8"
    assert result.raw_fields["verb"] == "get"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_k8s_audit_service_account_is_service() -> None:
    result = extract_entity_and_timestamp(SA, "k8s_audit", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_type == "service"
    assert result.entity_id == "coredns"
    assert result.raw_fields["src_ip"] == "10.0.0.11"
    assert result.raw_fields["sa_namespace"] == "kube-system"
