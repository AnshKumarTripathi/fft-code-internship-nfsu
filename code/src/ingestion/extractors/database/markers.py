"""Content-first and filename routing for database engines."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object

POSTGRES = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \S+ \[\d+\]"
    r"(?: [^@\s]+@\S+)? (?:LOG|ERROR|FATAL|PANIC|WARNING|STATEMENT):",
)
MYSQL_GENERAL = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\s+\d+\s+"
    r"(?:Query|Connect|Quit|Prepare|Execute|Rotate|Replica|Backup)\b"
)
MYSQL_SLOW = re.compile(r"# Query_time:")
MSSQL = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+spid\d+")
ORACLE_ORA = re.compile(r"\bORA-\d{5}\b")
ORACLE_START = re.compile(r"Starting ORACLE instance")
ORACLE_RMAN = re.compile(r"\bRMAN-\d+")
ORACLE_ARC = re.compile(r"\bARC\d:")
CASSANDRA = re.compile(
    r"\[Native-Transport-Requests|CassandraDaemon|org\.apache\.cassandra"
)
REDIS_ROLE = re.compile(r"^\d+:[MXSCE]\s")
REDIS_MONITOR = re.compile(r'^\d+\.\d+\s+\[\d+\s+[^\]]+\]\s+"[A-Z]+"')

_BASENAME_SOURCES = {
    "postgres.txt": "db_postgres",
    "postgres.log": "db_postgres",
    "postgresql.log": "db_postgres",
    "postgresql.txt": "db_postgres",
    "mysql.txt": "db_mysql",
    "mysql.log": "db_mysql",
    "mariadb.log": "db_mysql",
    "mariadb.txt": "db_mysql",
    "slow.log": "db_mysql",
    "mssql.txt": "db_mssql",
    "errorlog": "db_mssql",
    "oracle.txt": "db_oracle",
    "alert.log": "db_oracle",
    "mongodb.json": "db_mongodb",
    "mongod.log": "db_mongodb",
    "mongodb.txt": "db_mongodb",
    "cassandra.txt": "db_cassandra",
    "cassandra.log": "db_cassandra",
    "redis.txt": "db_redis",
    "redis.log": "db_redis",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("postgresql", "db_postgres"),
    ("postgres", "db_postgres"),
    ("mariadb", "db_mysql"),
    ("mysql", "db_mysql"),
    ("slow.log", "db_mysql"),
    ("mssql", "db_mssql"),
    ("mongodb", "db_mongodb"),
    ("mongod", "db_mongodb"),
    ("cassandra", "db_cassandra"),
    ("oracle", "db_oracle"),
    ("alert.log", "db_oracle"),
    ("redis.log", "db_redis"),
    ("redis.txt", "db_redis"),
)

_SKIP_NAMES = frozenset(
    {
        "system.log",
        "error.log",
        "access.log",
        "application.txt",
        "firewall.txt",
        "auth.log",
    }
)


def _is_mongo_obj(obj: dict) -> bool:
    if "c" not in obj or "id" not in obj:
        return False
    return "t" in obj or "s" in obj


def detect_database_log_source_from_line(line: str) -> str | None:
    """Return a db_* source from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_mongo_obj(obj):
            return "db_mongodb"
        return None
    stripped = line.strip()
    if POSTGRES.match(stripped):
        return "db_postgres"
    if MYSQL_GENERAL.match(stripped) or MYSQL_SLOW.search(stripped):
        return "db_mysql"
    if MSSQL.match(stripped):
        return "db_mssql"
    if (
        ORACLE_ORA.search(stripped)
        or ORACLE_START.search(stripped)
        or ORACLE_RMAN.search(stripped)
        or ORACLE_ARC.search(stripped)
    ):
        return "db_oracle"
    if CASSANDRA.search(stripped):
        return "db_cassandra"
    if REDIS_ROLE.match(stripped) or REDIS_MONITOR.match(stripped):
        return "db_redis"
    return None


def detect_database_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal system.log / error.log / access.log."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
