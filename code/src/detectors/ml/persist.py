"""Orchestrate Phase 7 / 53 detect-ml: parsed_events → ml_window_scores."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from src.config import ConfigError, ml_settings
from src.db.connection import (
    get_connection,
    record_run_finish,
    record_run_start,
    register_parquet_views,
)
from src.detectors.ml.autoencoder import (
    DEFAULT_AE_HIDDEN_DIMS,
    DEFAULT_AE_MAX_ITER,
    fit_autoencoder_bundle,
    score_windows_with_autoencoder,
)
from src.detectors.ml.ensemble import ensemble_summary_votes, fuse_ml_window_scores
from src.detectors.ml.isolation_forest import (
    MIN_EVENTS,
    TemplateWindow,
    fit_isolation_bundle,
    score_windows_with_bundle,
    slice_entity_windows,
)
from src.detectors.ml.onnx_scorer import ModelNotConfiguredError, score_windows_onnx
from src.detectors.ml.snapshots import (
    MlSnapshotError,
    load_autoencoder_snapshot,
    load_ml_snapshot,
    save_autoencoder_snapshot,
    save_ml_snapshot,
)
from src.detectors.ml.writers import (
    clear_ml_scores_output,
    clear_ml_window_scores_table,
    ml_scores_dir,
    sync_ml_window_scores_from_parquet,
    write_entity_ml_scores,
)
from src.ingestion.file_hash import hash_file_bytes
from src.timeseries.analysis_window import (
    attach_analysis_window_params,
    event_series_sql,
    execute_query,
    resolve_analysis_window,
)

logger = logging.getLogger(__name__)

ALLOWED_MODEL_TYPES = frozenset({"isolation_forest", "autoencoder", "onnx"})


@dataclass
class MlSummary:
    entities_scored: int = 0
    entities_skipped_empty: int = 0
    windows_total: int = 0
    windows_flagged: int = 0
    max_model_score: float = 0.0
    model_type: str = "isolation_forest"
    flagging: str = "mad_threshold"
    skipped_min_windows: bool = False
    model_snapshot_id: str | None = None
    ensemble_enabled: bool = False
    ensemble_fusion: str | None = None
    ensemble_models: list[str] | None = None
    ensemble_member_votes: dict[str, int] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class MlError(Exception):
    """Raised when detect-ml cannot proceed."""


def _validate_ml_config(config: dict[str, Any]) -> dict[str, Any]:
    try:
        settings = ml_settings(config)
    except ConfigError as exc:
        raise MlError(str(exc)) from exc

    model_type = settings.get("model_type", "isolation_forest")
    onnx_model_path = settings.get("onnx_model_path")
    window_buckets = config["statistical"]["window_buckets"]
    bucket_seconds = config["bucketing"]["bucket_seconds"]

    if model_type not in ALLOWED_MODEL_TYPES:
        raise MlError(
            f"ml.model_type must be one of {sorted(ALLOWED_MODEL_TYPES)}, "
            f"got {model_type!r}"
        )
    if not isinstance(window_buckets, int) or window_buckets <= 0:
        raise MlError(
            f"statistical.window_buckets must be a positive integer, got {window_buckets!r}"
        )
    if not isinstance(bucket_seconds, int) or bucket_seconds <= 0:
        raise MlError(
            f"bucketing.bucket_seconds must be a positive integer, got {bucket_seconds!r}"
        )

    settings["model_type"] = str(model_type)
    settings["window_seconds"] = window_buckets * bucket_seconds
    settings["bucket_seconds"] = bucket_seconds
    settings["onnx_model_path"] = onnx_model_path
    return settings


def _collect_windows(
    connection: Any,
    window_seconds: int,
    summary: MlSummary,
    *,
    analysis_window: Any = None,
) -> list[TemplateWindow]:
    """Stream parsed_events grouped by entity; return all eligible windows."""
    sql, sql_params = event_series_sql(analysis_window)
    relation = execute_query(connection, sql, sql_params)
    columns = [desc[0] for desc in relation.description]

    current_entity: str | None = None
    current_events: list[tuple[datetime, str]] = []
    all_windows: list[TemplateWindow] = []

    def flush() -> None:
        nonlocal current_entity, current_events
        if current_entity is None:
            return
        windows = slice_entity_windows(
            current_events,
            entity_id=current_entity,
            window_seconds=window_seconds,
            min_events=MIN_EVENTS,
        )
        if not windows:
            summary.entities_skipped_empty += 1
        all_windows.extend(windows)
        current_entity = None
        current_events = []

    while True:
        batch = relation.fetchmany(5000)
        for row in batch:
            record = dict(zip(columns, row))
            entity_id = str(record["entity_id"])
            ts = record["event_timestamp"]
            template_id = str(record["template_id"])
            if not isinstance(ts, datetime):
                continue
            if current_entity is None:
                current_entity = entity_id
            elif entity_id != current_entity:
                flush()
                current_entity = entity_id
            current_events.append((ts, template_id))
        if not batch:
            flush()
            break

    return all_windows


def _onnx_model_hash(onnx_model_path: str | Path | None) -> str | None:
    if onnx_model_path is None or str(onnx_model_path).strip() in ("", "null", "None"):
        return None
    path = Path(onnx_model_path)
    if not path.is_file():
        return None
    return hash_file_bytes(path).sha256


def _explain_top_k(config: dict[str, Any]) -> int:
    block = config.get("explainability") or {}
    if isinstance(block, dict) and block.get("ml_top_templates") is not None:
        try:
            return max(1, int(block["ml_top_templates"]))
        except (TypeError, ValueError):
            pass
    return 5


def _score_with_isolation_forest(
    windows: list[TemplateWindow],
    config: dict[str, Any],
    settings: dict[str, Any],
) -> tuple[list, str | None]:
    """Fit or reuse an IsolationBundle; return scores and snapshot id."""
    mode = str(settings.get("mode", "refit_and_snapshot"))
    baseline_dir = config["paths"]["baseline_dir"]
    flagging = settings["flagging"]
    mad_k = settings["mad_k"]
    score_threshold = settings["score_threshold"]
    contamination = settings["contamination"]
    top_k = _explain_top_k(config)

    if mode == "reuse_snapshot":
        try:
            bundle = load_ml_snapshot(baseline_dir, str(settings["snapshot_id"]))
        except MlSnapshotError as exc:
            raise MlError(str(exc)) from exc
        snapshot_id = str(settings["snapshot_id"])
        rows = score_windows_with_bundle(
            windows,
            bundle,
            flagging=flagging,
            score_threshold=score_threshold,
            mad_k=mad_k,
            model_snapshot_id=snapshot_id,
            top_k_features=top_k,
        )
        return rows, snapshot_id

    fitted = fit_isolation_bundle(windows, contamination=contamination)
    if fitted is None:
        return [], None
    bundle, raw_scores, predictions = fitted
    snapshot_id = save_ml_snapshot(baseline_dir, bundle)
    rows = score_windows_with_bundle(
        windows,
        bundle,
        flagging=flagging,
        score_threshold=score_threshold,
        mad_k=mad_k,
        model_snapshot_id=snapshot_id,
        raw_scores=raw_scores,
        predictions=predictions,
        top_k_features=top_k,
    )
    return rows, snapshot_id


def _score_with_autoencoder(
    windows: list[TemplateWindow],
    config: dict[str, Any],
    settings: dict[str, Any],
) -> tuple[list, str | None]:
    """Fit or reuse an AutoencoderBundle; return scores and snapshot id."""
    mode = str(settings.get("mode", "refit_and_snapshot"))
    baseline_dir = config["paths"]["baseline_dir"]
    flagging = settings["flagging"]
    mad_k = settings["mad_k"]
    score_threshold = settings["score_threshold"]
    top_k = _explain_top_k(config)
    hidden_dims = settings.get("ae_hidden_dims") or list(DEFAULT_AE_HIDDEN_DIMS)
    max_iter = int(settings.get("ae_max_iter") or DEFAULT_AE_MAX_ITER)

    if mode == "reuse_snapshot":
        try:
            bundle = load_autoencoder_snapshot(
                baseline_dir, str(settings["snapshot_id"])
            )
        except MlSnapshotError as exc:
            raise MlError(str(exc)) from exc
        snapshot_id = str(settings["snapshot_id"])
        rows = score_windows_with_autoencoder(
            windows,
            bundle,
            flagging=flagging,
            score_threshold=score_threshold,
            mad_k=mad_k,
            model_snapshot_id=snapshot_id,
            top_k_features=top_k,
        )
        return rows, snapshot_id

    fitted = fit_autoencoder_bundle(
        windows, hidden_dims=hidden_dims, max_iter=max_iter
    )
    if fitted is None:
        return [], None
    bundle, raw_scores, residuals = fitted
    snapshot_id = save_autoencoder_snapshot(baseline_dir, bundle)
    rows = score_windows_with_autoencoder(
        windows,
        bundle,
        flagging=flagging,
        score_threshold=score_threshold,
        mad_k=mad_k,
        model_snapshot_id=snapshot_id,
        raw_scores=raw_scores,
        residuals=residuals,
        top_k_features=top_k,
    )
    return rows, snapshot_id


def _score_with_onnx(
    windows: list[TemplateWindow],
    config: dict[str, Any],
    settings: dict[str, Any],
) -> tuple[list, str | None]:
    """Score with a frozen ONNX model; never falls through to IsolationForest."""
    top_k = _explain_top_k(config)
    rows = score_windows_onnx(
        windows,
        onnx_model_path=settings.get("onnx_model_path"),
        flagging=settings["flagging"],
        score_threshold=settings["score_threshold"],
        mad_k=settings["mad_k"],
        top_k_features=top_k,
    )
    snapshot_id = None
    if rows:
        snapshot_id = rows[0].model_snapshot_id
    return rows, snapshot_id


def _score_with_ensemble(
    windows: list[TemplateWindow],
    config: dict[str, Any],
    settings: dict[str, Any],
) -> tuple[list, str | None]:
    """Score IF + AE and fuse flags; return fused rows and primary snapshot id."""
    ensemble = settings.get("ensemble") or {}
    models = list(ensemble.get("models") or ["isolation_forest", "autoencoder"])
    fusion = str(ensemble.get("fusion") or "majority")

    member_rows: dict[str, list] = {}
    snapshot_ids: dict[str, str | None] = {}

    for model_name in models:
        if model_name == "isolation_forest":
            rows, snapshot_id = _score_with_isolation_forest(
                windows, config, settings
            )
        elif model_name == "autoencoder":
            rows, snapshot_id = _score_with_autoencoder(windows, config, settings)
        else:
            raise MlError(
                f"ml.ensemble does not support model {model_name!r} "
                "(use isolation_forest and autoencoder)"
            )
        member_rows[model_name] = list(rows)
        snapshot_ids[model_name] = snapshot_id

    if any(not rows for rows in member_rows.values()):
        missing = [name for name, rows in member_rows.items() if not rows]
        raise MlError(
            "ml.ensemble could not score all members "
            f"(empty results for: {', '.join(missing)})"
        )

    fused = fuse_ml_window_scores(member_rows, fusion=fusion)
    primary = snapshot_ids.get("isolation_forest") or next(
        (sid for sid in snapshot_ids.values() if sid), None
    )
    return fused, primary


def run_detect_ml(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
) -> MlSummary:
    """Score template sequences from ``parsed_events`` into ``ml_window_scores``."""
    connection = get_connection(config)
    summary = MlSummary()
    settings = _validate_ml_config(config)
    ensemble = settings.get("ensemble") or {}
    ensemble_enabled = bool(ensemble.get("enabled"))
    model_type = "ensemble" if ensemble_enabled else settings["model_type"]
    contamination = settings["contamination"]
    window_seconds = settings["window_seconds"]
    bucket_seconds = settings["bucket_seconds"]
    onnx_model_path = settings["onnx_model_path"]
    flagging = settings["flagging"]
    mad_k = settings["mad_k"]
    score_threshold = settings["score_threshold"]
    min_windows_to_fit = settings["min_windows_to_fit"]
    summary.model_type = model_type
    summary.flagging = flagging
    summary.ensemble_enabled = ensemble_enabled
    if ensemble_enabled:
        summary.ensemble_fusion = str(ensemble.get("fusion") or "majority")
        summary.ensemble_models = list(
            ensemble.get("models") or ["isolation_forest", "autoencoder"]
        )
    scores_dir = ml_scores_dir(config)
    params = {
        "config_path": config_path,
        "scores_dir": str(scores_dir),
        "model_type": model_type,
        "contamination": contamination,
        "flagging": flagging,
        "mad_k": mad_k,
        "score_threshold": score_threshold,
        "min_windows_to_fit": min_windows_to_fit,
        "window_seconds": window_seconds,
        "bucket_seconds": bucket_seconds,
        "min_events": MIN_EVENTS,
        "onnx_model_path": onnx_model_path,
        "ae_hidden_dims": settings.get("ae_hidden_dims"),
        "ae_max_iter": settings.get("ae_max_iter"),
        "n_windows": 0,
        "n_flagged": 0,
        "ml_mode": settings.get("mode"),
        "ml_snapshot_id": settings.get("snapshot_id"),
        "ensemble_enabled": ensemble_enabled,
        "ensemble_fusion": summary.ensemble_fusion,
        "ensemble_models": summary.ensemble_models,
    }
    analysis_window = resolve_analysis_window(config, connection, source="events")
    attach_analysis_window_params(params, analysis_window)
    run_id = record_run_start(connection, stage="detect-ml", params=params)

    try:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM parsed_events"
        ).fetchone()[0]
        if int(event_count) == 0:
            raise MlError("No parsed_events found; run parse first")

        clear_ml_scores_output(config)
        clear_ml_window_scores_table(connection)

        windows = _collect_windows(
            connection,
            window_seconds,
            summary,
            analysis_window=analysis_window,
        )
        n_windows = len(windows)
        params["n_windows"] = n_windows
        onnx_hash = _onnx_model_hash(onnx_model_path)
        params["manifest"]["onnx_model_hash"] = onnx_hash

        # ONNX validates configuration before the cold-start skip so misconfig
        # is never silent, then scores without falling through to IF.
        if model_type == "onnx":
            try:
                rows, model_snapshot_id = _score_with_onnx(windows, config, settings)
            except ModelNotConfiguredError:
                raise
        else:
            ml_mode = str(settings.get("mode", "refit_and_snapshot"))
            skip_fit = ml_mode != "reuse_snapshot" and n_windows < min_windows_to_fit
            if skip_fit:
                summary.skipped_min_windows = True
                params["skipped_min_windows"] = True
                params["n_flagged"] = 0
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
                logger.info(
                    "detect-ml skipped: %d windows < min_windows_to_fit=%d",
                    n_windows,
                    min_windows_to_fit,
                )
                print("detect-ml summary:")
                print(f"  flagging={flagging} flagged=0/{n_windows} windows")
                print("  skipped_min_windows: true")
                return summary

            try:
                if ensemble_enabled:
                    rows, model_snapshot_id = _score_with_ensemble(
                        windows, config, settings
                    )
                elif settings["model_type"] == "autoencoder":
                    rows, model_snapshot_id = _score_with_autoencoder(
                        windows, config, settings
                    )
                else:
                    rows, model_snapshot_id = _score_with_isolation_forest(
                        windows, config, settings
                    )
            except MlSnapshotError as exc:
                raise MlError(str(exc)) from exc

        summary.model_snapshot_id = model_snapshot_id
        params["manifest"]["model_snapshot_id"] = model_snapshot_id
        if ensemble_enabled:
            summary.ensemble_member_votes = ensemble_summary_votes(rows)
            params["ensemble_member_votes"] = summary.ensemble_member_votes

        by_entity: dict[str, list] = defaultdict(list)
        for row in rows:
            by_entity[row.entity_id].append(row)

        for entity_id, entity_rows in by_entity.items():
            path = write_entity_ml_scores(scores_dir, entity_id, entity_rows)
            if path is None:
                continue
            summary.entities_scored += 1
            summary.windows_total += len(entity_rows)
            summary.windows_flagged += sum(1 for r in entity_rows if r.flagged)
            entity_max = max(r.model_score for r in entity_rows)
            if entity_max > summary.max_model_score:
                summary.max_model_score = entity_max

        params["n_flagged"] = summary.windows_flagged
        if summary.entities_scored > 0:
            sync_ml_window_scores_from_parquet(
                connection, scores_dir, run_id=run_id, config=config
            )
        register_parquet_views(connection, config)

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

        logger.info("detect-ml summary: %s", summary.as_dict())
        print("detect-ml summary:")
        print(
            f"  flagging={flagging} flagged="
            f"{summary.windows_flagged}/{summary.windows_total} windows"
        )
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except (MlError, ModelNotConfiguredError):
        record_run_finish(connection, run_id, "failed")
        raise
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()
