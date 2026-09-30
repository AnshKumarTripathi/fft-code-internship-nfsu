"""Veeam, Commvault, and Bacula all resolve to backup (Phase 32)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "virtualization"

_PRODUCT_FILES = {
    "veeam": "veeam.txt",
    "commvault": "commvault.txt",
    "bacula": "bacula.txt",
}


@pytest.mark.parametrize("product", sorted(_PRODUCT_FILES))
def test_backup_product_extracts(product: str) -> None:
    path = FIXTURE_DIR / _PRODUCT_FILES[product]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    assert resolve_log_source(path, lines[0]) == "backup"
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, "backup", default_year=2024)
        if result.extraction_ok:
            ok += 1
    assert ok >= 1
