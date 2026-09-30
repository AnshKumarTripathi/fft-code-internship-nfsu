"""AWS RDS vs local PostgreSQL isolation (Phase 27)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

RDS = "2024-01-15 10:00:01 UTC:10.0.1.5(54321):alice@appdb:[12345]:LOG: statement: SELECT 1"
POSTGRES = "2024-01-15 10:00:01.123 UTC [12345] alice@appdb LOG:  statement: SELECT 1"


def test_rds_prefix_is_aws_rds() -> None:
    assert detect_log_source_from_line(RDS) == "aws_rds"
    assert resolve_log_source(Path("postgres.log"), RDS) == "aws_rds"


def test_local_postgres_stays_db_postgres() -> None:
    assert detect_log_source_from_line(POSTGRES) == "db_postgres"
    assert resolve_log_source(Path("rds.txt"), POSTGRES) == "db_postgres"
