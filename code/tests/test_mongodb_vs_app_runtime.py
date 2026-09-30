"""MongoDB JSON vs Phase 25 app_runtime isolation (Phase 26)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

MONGO = (
    '{"t":{"$date":"2024-01-15T10:00:01.000Z"},"s":"I","c":"NETWORK","id":22943,'
    '"ctx":"listener","msg":"Connection accepted",'
    '"attr":{"remote":"10.0.0.8:54321","connectionId":1}}'
)
APP = (
    '{"ts":"2024-01-15T10:00:01.000Z","level":"info","msg":"server started",'
    '"service":"api","host":"app-01"}'
)


def test_mongo_json_is_db_mongodb() -> None:
    assert detect_log_source_from_line(MONGO) == "db_mongodb"
    assert resolve_log_source(Path("app_runtime.json"), MONGO) == "db_mongodb"


def test_app_runtime_stays_app_runtime() -> None:
    assert detect_log_source_from_line(APP) == "app_runtime"
    assert resolve_log_source(Path("mongodb.json"), APP) == "app_runtime"
    assert detect_log_source_from_line(APP) != "db_mongodb"


def test_mixed_json_file_content_first(tmp_path: Path) -> None:
    mixed = tmp_path / "mixed.json"
    mixed.write_text(MONGO + "\n" + APP + "\n", encoding="utf-8")
    assert resolve_log_source(mixed, MONGO) == "db_mongodb"
    assert resolve_log_source(mixed, APP) == "app_runtime"
