"""collab_audit vs Phase 27 saas_m365 isolation (Phase 29)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

COLLAB = (
    '{"platform":"slack","actor":"alice","action":"file_share",'
    '"workspace":"T123","ip":"203.0.113.10","ts":"2024-01-15T10:00:01Z"}'
)
M365 = (
    '{"CreationTime":"2024-01-15T10:00:01","UserId":"alice@contoso.com",'
    '"Operation":"MailItemsAccessed","Workload":"Exchange","ClientIP":"10.0.0.11"}'
)


def test_collab_json_is_collab_audit() -> None:
    assert detect_log_source_from_line(COLLAB) == "collab_audit"
    assert resolve_log_source(Path("m365.json"), COLLAB) == "collab_audit"
    result = extract_entity_and_timestamp(COLLAB, "collab_audit", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields.get("platform") == "slack"
    assert result.raw_fields.get("src_ip") == "203.0.113.10"


def test_m365_ual_stays_saas_m365() -> None:
    assert detect_log_source_from_line(M365) == "saas_m365"
    assert resolve_log_source(Path("collab.json"), M365) == "saas_m365"
    result = extract_entity_and_timestamp(M365, "saas_m365", default_year=1999)
    assert result.extraction_ok is True
    assert result.raw_fields.get("workload") == "Exchange"
