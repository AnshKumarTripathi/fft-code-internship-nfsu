"""Stable UUID5 / BIGINT identities (R5)."""

from __future__ import annotations

import uuid

NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://nfsu.fft.local/r5-identities")
INGEST_ROW_NS = uuid.uuid5(NAMESPACE, "ingest_row_id")
EVENT_NS = uuid.uuid5(NAMESPACE, "event_id")
CLUSTER_RUN_NS = uuid.uuid5(NAMESPACE, "cluster_run_id")
PIPELINE_ERROR_NS = uuid.uuid5(NAMESPACE, "pipeline_errors")


def uuid5_str(namespace: uuid.UUID, name: str) -> str:
    return str(uuid.uuid5(namespace, name))


def uuid5_bigint(namespace: uuid.UUID, name: str) -> int:
    """Positive signed BIGINT (63-bit) derived from UUID5. Never 0."""
    value = uuid.uuid5(namespace, name).int & 0x7FFFFFFFFFFFFFFF
    return value or 1


def stable_ingest_row_id(file_sha256: str, line_number: int) -> str:
    """UUID5 of source-file SHA-256 + line number (R4 file hash + R5)."""
    return uuid5_str(INGEST_ROW_NS, f"{file_sha256}:{int(line_number)}")


def stable_event_id(
    parser_snapshot_id: str,
    content_hash: str,
    line_number: int,
    source_path: str,
) -> int:
    """BIGINT event_id: snapshot + content_hash + line + path."""
    name = (
        f"{parser_snapshot_id}|{content_hash}|{int(line_number)}|{source_path}"
    )
    return uuid5_bigint(EVENT_NS, name)
