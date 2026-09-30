"""Orchestrate Phase 80 normalize stage."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.config import normalize_settings, pipeline_ui_settings
from src.db.connection import get_connection, record_run_finish, record_run_start
from src.ingestion.file_hash import hash_file_bytes
from src.normalize.detect import (
    PASSTHROUGH_KIND,
    UNSUPPORTED_KIND,
    detect_converter_kind,
    is_passthrough_suffix,
    iter_input_files,
)
from src.normalize.models import ConverterError, NormalizeError, NormalizeSummary
from src.normalize.registry import KNOWN_CONVERTERS, run_converter
from src.normalize.writers import (
    clear_normalize_dead_letter,
    clear_normalize_output,
    copy_passthrough,
    ensure_normalize_dirs,
    normalize_output_dir,
    write_dead_letter_row,
    write_manifest_row,
)

logger = logging.getLogger(__name__)


def resolve_normalize_input_dir(config: dict[str, Any], settings: dict[str, Any]) -> Path:
    """``input_dir: null`` → ``pipeline_ui.upload_dir`` (Policy B)."""
    raw = settings.get("input_dir")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        ui = pipeline_ui_settings(config)
        return Path(str(ui["upload_dir"]))
    return Path(str(raw))


def _handle_unsupported(
    settings: dict[str, Any],
    *,
    source: Path,
    reason: str,
    converter_tried: str | None,
    message: str | None,
    summary: NormalizeSummary,
) -> None:
    mode = str(settings["on_unsupported"])
    if mode == "fail":
        raise NormalizeError(
            message or f"unsupported normalize input: {source} ({reason})"
        )
    if mode == "skip":
        return
    # dead_letter
    write_dead_letter_row(
        settings,
        source_path=str(source),
        reason=reason,
        converter_tried=converter_tried,
        message=message,
    )
    summary.dead_lettered += 1
    if reason == "converter_unavailable":
        summary.converter_unavailable += 1


def run_normalize(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
) -> NormalizeSummary:
    """Expand archives under input into ``normalize.output_dir``.

    When enabled and the stage completes (including empty-of-useful-outputs
    runs that still scanned input), mutates ``config["paths"]["raw_log_dir"]``
    to ``output_dir`` so subsequent ingest in the same process only reads
    normalized files (Policy B). Empty input skips without override.
    """
    settings = normalize_settings(config)
    connection = get_connection(config)
    summary = NormalizeSummary()
    input_dir = resolve_normalize_input_dir(config, settings)
    output_dir = normalize_output_dir(settings)
    summary.input_dir = str(input_dir)
    summary.output_dir = str(output_dir)

    params: dict[str, Any] = {
        "config_path": config_path,
        "enabled": settings["enabled"],
        "input_dir": str(input_dir),
        "output_dir": str(output_dir),
        "converters": list(settings["converters"]),
        "on_unsupported": settings["on_unsupported"],
    }
    run_id = record_run_start(connection, stage="normalize", params=params)

    try:
        if not settings["enabled"]:
            summary.skipped_disabled = True
            params_with_summary = {**params, "summary": summary.as_dict()}
            connection.execute(
                """
                UPDATE pipeline_runs
                SET params_json = ?::JSON
                WHERE run_id = ?
                """,
                [json.dumps(params_with_summary), run_id],
            )
            record_run_finish(connection, run_id, "success")
            print("normalize: disabled (normalize.enabled=false)")
            return summary

        ensure_normalize_dirs(settings)
        if settings["clear_output_on_run"]:
            clear_normalize_output(settings)
            clear_normalize_dead_letter(settings)
        else:
            ensure_normalize_dirs(settings)

        files = iter_input_files(input_dir)
        if not files:
            summary.skipped_empty = True
            params_with_summary = {**params, "summary": summary.as_dict()}
            connection.execute(
                """
                UPDATE pipeline_runs
                SET params_json = ?::JSON
                WHERE run_id = ?
                """,
                [json.dumps(params_with_summary), run_id],
            )
            record_run_finish(connection, run_id, "success")
            print("normalize: soft-skip (empty input)")
            return summary

        enabled_converters = set(settings["converters"])
        unknown = enabled_converters - set(KNOWN_CONVERTERS)
        if unknown:
            raise NormalizeError(
                f"normalize.converters has unknown ids: {sorted(unknown)}"
            )

        bytes_out_running = 0
        passthrough_suffixes = list(settings["allow_suffixes_passthrough"])

        for source in files:
            summary.files_in += 1
            try:
                source_digest = hash_file_bytes(source)
            except OSError as exc:
                _handle_unsupported(
                    settings,
                    source=source,
                    reason="open_failed",
                    converter_tried=None,
                    message=str(exc),
                    summary=summary,
                )
                continue

            summary.bytes_in += source_digest.size_bytes
            try:
                relative_base = str(source.relative_to(input_dir)).replace("\\", "/")
            except ValueError:
                relative_base = source.name

            kind = detect_converter_kind(source)
            if kind == UNSUPPORTED_KIND:
                if is_passthrough_suffix(source, passthrough_suffixes):
                    kind = PASSTHROUGH_KIND
                else:
                    _handle_unsupported(
                        settings,
                        source=source,
                        reason="unsupported_type",
                        converter_tried=None,
                        message=f"no converter for {source.name}",
                        summary=summary,
                    )
                    continue

            if kind == PASSTHROUGH_KIND or (
                kind == UNSUPPORTED_KIND
                and is_passthrough_suffix(source, passthrough_suffixes)
            ):
                dest = output_dir / relative_base
                try:
                    written = copy_passthrough(source, dest)
                    out_digest = hash_file_bytes(dest)
                except OSError as exc:
                    _handle_unsupported(
                        settings,
                        source=source,
                        reason="passthrough_failed",
                        converter_tried="passthrough",
                        message=str(exc),
                        summary=summary,
                    )
                    continue
                write_manifest_row(
                    output_dir,
                    source_path=str(source),
                    output_path=str(dest),
                    converter="passthrough",
                    source_sha256=source_digest.sha256,
                    output_sha256=out_digest.sha256,
                    bytes_in=source_digest.size_bytes,
                    bytes_out=written,
                )
                summary.files_out += 1
                summary.files_passthrough += 1
                summary.bytes_out += written
                bytes_out_running += written
                continue

            # Re-check passthrough when detect returned unsupported but suffix allowed
            if kind not in enabled_converters:
                if is_passthrough_suffix(source, passthrough_suffixes):
                    dest = output_dir / relative_base
                    written = copy_passthrough(source, dest)
                    out_digest = hash_file_bytes(dest)
                    write_manifest_row(
                        output_dir,
                        source_path=str(source),
                        output_path=str(dest),
                        converter="passthrough",
                        source_sha256=source_digest.sha256,
                        output_sha256=out_digest.sha256,
                        bytes_in=source_digest.size_bytes,
                        bytes_out=written,
                    )
                    summary.files_out += 1
                    summary.files_passthrough += 1
                    summary.bytes_out += written
                    bytes_out_running += written
                    continue
                _handle_unsupported(
                    settings,
                    source=source,
                    reason="converter_disabled",
                    converter_tried=kind,
                    message=f"converter {kind!r} not in normalize.converters",
                    summary=summary,
                )
                continue

            try:
                result = run_converter(
                    kind,
                    source,
                    output_dir,
                    relative_base=relative_base,
                    settings=settings,
                    bytes_written_so_far=bytes_out_running,
                )
            except ConverterError as exc:
                _handle_unsupported(
                    settings,
                    source=source,
                    reason=exc.reason,
                    converter_tried=kind,
                    message=str(exc),
                    summary=summary,
                )
                continue

            for converted in result.files:
                out_digest = hash_file_bytes(converted.output_path)
                write_manifest_row(
                    output_dir,
                    source_path=str(source),
                    output_path=str(converted.output_path),
                    converter=converted.converter,
                    source_sha256=source_digest.sha256,
                    output_sha256=out_digest.sha256,
                    bytes_in=source_digest.size_bytes,
                    bytes_out=converted.bytes_out,
                )
                summary.files_out += 1
                summary.bytes_out += converted.bytes_out
                bytes_out_running += converted.bytes_out
            summary.files_converted += 1

        # Policy B: subsequent ingest in this process reads only normalized/
        config["paths"]["raw_log_dir"] = str(output_dir)

        params_with_summary = {**params, "summary": summary.as_dict()}
        connection.execute(
            """
            UPDATE pipeline_runs
            SET params_json = ?::JSON
            WHERE run_id = ?
            """,
            [json.dumps(params_with_summary), run_id],
        )
        record_run_finish(connection, run_id, "success")
        logger.info("normalize summary: %s", summary.as_dict())
        print("normalize summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
