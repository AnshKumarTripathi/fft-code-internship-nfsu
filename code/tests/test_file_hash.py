"""R4 file-byte SHA-256 and staging Merkle."""

from __future__ import annotations

import hashlib
from pathlib import Path

from src.ingestion.file_hash import hash_bytes, hash_file_bytes, merkle_sha256


def test_same_bytes_same_file_hash(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    path.write_bytes(b"hello\nworld\n")
    first = hash_file_bytes(path)
    second = hash_file_bytes(path)
    assert first.sha256 == second.sha256
    assert first.sha256 == hashlib.sha256(b"hello\nworld\n").hexdigest()
    assert first.size_bytes == 12
    assert first.source_path == str(path)


def test_mutate_one_byte_changes_file_hash(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    path.write_bytes(b"hello\nworld\n")
    before = hash_file_bytes(path).sha256
    path.write_bytes(b"hello\nworle\n")
    after = hash_file_bytes(path).sha256
    assert before != after


def test_merkle_is_order_independent() -> None:
    a = hash_bytes(b"part-a")
    b = hash_bytes(b"part-b")
    assert merkle_sha256([a, b]) == merkle_sha256([b, a])
    assert merkle_sha256([a, b]) != merkle_sha256([a])


def test_empty_merkle_is_sha256_of_empty() -> None:
    assert merkle_sha256([]) == hashlib.sha256(b"").hexdigest()
