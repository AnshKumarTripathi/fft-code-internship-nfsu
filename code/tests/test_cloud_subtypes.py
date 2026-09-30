"""Parametrized cloud subtype extractors (Phase 27)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.cloud import CLOUD_LOG_SOURCES
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "cloud"

_FILE_FOR_SOURCE = {
    "aws_cloudtrail": "cloudtrail.json",
    "aws_vpcflow": "vpcflow.txt",
    "aws_s3": "s3.txt",
    "aws_elb": "alb.txt",
    "aws_guardduty": "guardduty.json",
    "aws_config": "aws_config.json",
    "aws_lambda": "lambda.txt",
    "aws_rds": "rds.txt",
    "azure_activity": "azure_activity.json",
    "azure_ad": "azure_ad.json",
    "azure_nsg": "nsg.json",
    "azure_monitor": "monitor.json",
    "azure_keyvault": "keyvault.json",
    "gcp_audit": "gcp_audit.json",
    "gcp_vpcflow": "gcp_vpcflow.json",
    "gcp_lb": "gcp_lb.json",
    "gcp_iam": "gcp_iam.json",
    "casb": "casb.json",
    "saas_workspace": "workspace.json",
    "saas_m365": "m365.json",
    "saas_salesforce": "salesforce.json",
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


def test_all_cloud_sources_have_fixtures() -> None:
    missing = [
        source
        for source in sorted(CLOUD_LOG_SOURCES)
        if not (FIXTURE_DIR / _FILE_FOR_SOURCE[source]).is_file()
    ]
    assert missing == []
