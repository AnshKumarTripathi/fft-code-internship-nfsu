"""Suffix + magic-byte detection for normalize converters."""

from __future__ import annotations

from pathlib import Path

# Magic signatures (prefix match)
_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZ"
_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_EMPTY_MAGIC = b"PK\x05\x06"
_TAR_USTAR = b"ustar"

SKIP_NAMES = frozenset({".gitkeep", ".DS_Store"})

PASSTHROUGH_KIND = "passthrough"
UNSUPPORTED_KIND = "unsupported"

# Converter ids matching YAML / registry
KIND_GUNZIP = "gunzip"
KIND_BUNZIP2 = "bunzip2"
KIND_UNZIP = "unzip"
KIND_TAR = "tar"
KIND_EVTX = "evtx_text"
KIND_JOURNAL = "journal_export"

_EVTX_MAGIC = b"ElfFile\x00"


def _read_prefix(path: Path, size: int = 512) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def _lower_name(path: Path) -> str:
    return path.name.lower()


def is_tar_gz_name(name: str) -> bool:
    lower = name.lower()
    return lower.endswith(".tar.gz") or lower.endswith(".tgz") or lower.endswith(".tar.bz2")


def detect_converter_kind(path: Path) -> str:
    """Return converter id, ``passthrough``, or ``unsupported``.

    Suffix wins for known archive extensions; magic bytes break ties for
    extensionless or mislabeled files. ``.tar.gz`` / ``.tgz`` / ``.tar.bz2``
    route to ``tar``, not ``gunzip`` / ``bunzip2``.
    """
    name = _lower_name(path)
    if is_tar_gz_name(name) or name.endswith(".tar"):
        return KIND_TAR
    if name.endswith(".zip"):
        return KIND_UNZIP
    if name.endswith(".bz2") and not name.endswith(".tar.bz2"):
        return KIND_BUNZIP2
    if name.endswith(".gz") and not name.endswith(".tar.gz"):
        return KIND_GUNZIP
    if name.endswith(".evtx") or name.endswith(".evt"):
        return KIND_EVTX
    if name.endswith(".journal"):
        return KIND_JOURNAL

    prefix = _read_prefix(path)
    if prefix.startswith(_EVTX_MAGIC):
        return KIND_EVTX
    if prefix.startswith(_GZIP_MAGIC):
        # Could be .tar.gz without suffix — prefer tar if ustar after gzip is heavy;
        # MVP: gunzip stream for bare gzip magic without tar suffix.
        return KIND_GUNZIP
    if prefix.startswith(_BZIP2_MAGIC):
        return KIND_BUNZIP2
    if prefix.startswith(_ZIP_MAGIC) or prefix.startswith(_ZIP_EMPTY_MAGIC):
        return KIND_UNZIP
    # POSIX tar often has "ustar" at offset 257
    if len(prefix) >= 262 and prefix[257:262] == _TAR_USTAR:
        return KIND_TAR

    return UNSUPPORTED_KIND


def is_passthrough_suffix(path: Path, allowed: list[str]) -> bool:
    suffix = path.suffix.lower()
    allowed_set = {s.lower() if s.startswith(".") else f".{s.lower()}" for s in allowed}
    # .tar.gz is not passthrough
    if is_tar_gz_name(path.name):
        return False
    return suffix in allowed_set


def iter_input_files(input_dir: Path) -> list[Path]:
    """Sorted files under ``input_dir`` (non-recursive top-level only for MVP).

    Uploads land flat under ``upload_dir``. Recurse one level of subdirs if
    present, but skip reserved names.
    """
    if not input_dir.is_dir():
        return []
    skip_dirs = {"normalize_dead_letter", "normalized"}
    found: list[Path] = []
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in SKIP_NAMES:
            continue
        parts = {p.lower() for p in path.relative_to(input_dir).parts[:-1]}
        if parts & skip_dirs:
            continue
        found.append(path)
    return found
