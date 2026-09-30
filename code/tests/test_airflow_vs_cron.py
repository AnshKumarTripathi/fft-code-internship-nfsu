"""Airflow vs linux_cron isolation (Phase 31)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

AIRFLOW = (
    "[2024-01-15 10:00:01,123] {taskinstance.py:1159} INFO - DAG: etl_daily Task: extract"
)
CRON = 'Jan 15 10:00:01 testhost CRON[1234]: (alice) CMD (/usr/bin/backup.sh)'


def test_airflow_is_not_linux_cron() -> None:
    assert detect_log_source_from_line(AIRFLOW) == "airflow"
    assert resolve_log_source(Path("cron.log"), AIRFLOW) == "airflow"


def test_cron_stays_linux_cron() -> None:
    assert detect_log_source_from_line(CRON) == "linux_cron"
    assert resolve_log_source(Path("airflow.txt"), CRON) == "linux_cron"
