"""Orchestrate Phase 15 evaluate: labels + warehouse flags → metrics files."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import evaluation_settings
from src.db.connection import get_connection, record_run_finish, record_run_start
from src.evaluation.labels import EvaluationError, LabelRow, load_labels
from src.evaluation.metrics import Detection, DetectorMetrics, score_detections

logger = logging.getLogger(__name__)

DETECTOR_SOURCES: tuple[tuple[str, str], ...] = (
    ("statistical", "statistical_window_scores"),
    ("spectral", "spectral_window_scores"),
    ("ml", "ml_window_scores"),
    ("changepoint", "changepoint_window_scores"),
    ("seasonal", "seasonal_window_scores"),
)

DEFAULT_NOTES = [
    "unlabeled ignored",
    "combined = incidents overlapping attacker windows",
]


@dataclass
class EvaluateSummary:
    labels_path: str = ""
    labels_loaded: int = 0
    detectors_scored: list[str] = field(default_factory=list)
    entity_labels_written: int = 0
    metrics_json_path: str = ""
    metrics_md_path: str = ""
    cold_start_rows: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_evaluate(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    cold_start_synthetic: bool = False,
) -> EvaluateSummary:
    """Score warehouse detections against a labels file; write JSON + Markdown."""
    settings = evaluation_settings(config)
    labels_path = settings.get("labels_path")
    if not labels_path:
        raise EvaluationError(
            "evaluation.labels_path is required (CSV or Parquet of entity/window labels)"
        )

    labels = load_labels(labels_path)
    output_dir = Path(str(settings["output_dir"]))
    output_dir.mkdir(parents=True, exist_ok=True)

    connection = get_connection(config)
    params = {
        "config_path": config_path,
        "labels_path": str(labels_path),
        "output_dir": str(output_dir),
        "overlap_rule": settings["overlap_rule"],
        "write_entity_labels": settings["write_entity_labels"],
        "cold_start_synthetic": cold_start_synthetic,
    }
    run_id = record_run_start(connection, stage="evaluate", params=params)
    summary = EvaluateSummary(labels_path=str(labels_path), labels_loaded=len(labels))

    try:
        detections_by_source = _load_detections_by_source(connection)
        overlap_rule = str(settings["overlap_rule"])
        detector_metrics: dict[str, DetectorMetrics] = {}
        for source, detections in detections_by_source.items():
            detector_metrics[source] = score_detections(
                labels,
                detections,
                overlap_rule=overlap_rule,  # type: ignore[arg-type]
            )

        if settings["write_entity_labels"]:
            summary.entity_labels_written = _write_entity_labels(connection, labels)

        cold_start_table: list[dict[str, Any]] = []
        if cold_start_synthetic:
            from src.evaluation.cold_start import measure_spectral_cold_start

            cold_start_table = [
                row.as_dict() for row in measure_spectral_cold_start()
            ]
            summary.cold_start_rows = len(cold_start_table)

        payload = {
            "overlap_rule": settings["overlap_rule"],
            "labels_path": str(labels_path),
            "detectors": {
                name: metrics.as_dict() for name, metrics in detector_metrics.items()
            },
            "notes": list(DEFAULT_NOTES),
        }
        if cold_start_table:
            payload["cold_start"] = cold_start_table

        json_path = output_dir / "metrics.json"
        md_path = output_dir / "metrics.md"
        json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        md_path.write_text(
            _render_metrics_markdown(payload, cold_start_table),
            encoding="utf-8",
        )
        summary.metrics_json_path = str(json_path)
        summary.metrics_md_path = str(md_path)
        summary.detectors_scored = list(detector_metrics)

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

        logger.info("evaluate summary: %s", summary.as_dict())
        print("evaluate summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except EvaluationError:
        record_run_finish(connection, run_id, "failed")
        raise
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()


def _table_exists(connection: Any, table_name: str) -> bool:
    row = connection.execute(
        """
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_name = ? AND table_schema = 'main'
        """,
        [table_name],
    ).fetchone()
    return bool(row and int(row[0]) > 0)


def _load_detections_by_source(connection: Any) -> dict[str, list[Detection]]:
    """Load flagged windows. Schema stubs with 0 rows are treated as missing."""
    result: dict[str, list[Detection]] = {}
    for source, table_name in DETECTOR_SOURCES:
        if not _table_has_rows(connection, table_name):
            continue
        rows = connection.execute(
            f"""
            SELECT entity_id, window_start, window_end
            FROM {table_name}
            WHERE flagged = TRUE
            """
        ).fetchall()
        result[source] = _rows_to_detections(rows)

    if _source_row_count(
        connection,
        "anomaly_events",
        "source_detector = 'cluster_outlier'",
    ):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end
            FROM anomaly_events
            WHERE source_detector = 'cluster_outlier'
            """
        ).fetchall()
        result["cluster_outlier"] = _rows_to_detections(rows)

    if _table_has_rows(connection, "incidents"):
        rows = connection.execute(
            """
            SELECT entity_id, start_time, end_time
            FROM incidents
            """
        ).fetchall()
        result["combined"] = _rows_to_detections(rows)

    return result


def _table_has_rows(connection: Any, table_name: str) -> bool:
    if not _table_exists(connection, table_name):
        return False
    row = connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
    return bool(row and int(row[0]) > 0)


def _source_row_count(connection: Any, table_name: str, where_sql: str) -> bool:
    if not _table_exists(connection, table_name):
        return False
    row = connection.execute(
        f"SELECT COUNT(*) FROM {table_name} WHERE {where_sql}"
    ).fetchone()
    return bool(row and int(row[0]) > 0)


def _rows_to_detections(rows: list[Any]) -> list[Detection]:
    detections: list[Detection] = []
    for entity_id, window_start, window_end in rows:
        if not isinstance(window_start, datetime):
            continue
        end = window_end if isinstance(window_end, datetime) else window_start
        detections.append(
            Detection(
                entity_id=str(entity_id),
                window_start=_ensure_utc(window_start),
                window_end=_ensure_utc(end),
            )
        )
    return detections


def _write_entity_labels(connection: Any, labels: list[LabelRow]) -> int:
    """UPDATE entities.label for matching entity_id; attacker wins if both."""
    by_entity: dict[str, str] = {}
    for row in labels:
        if row.label == "attacker":
            by_entity[row.entity_id] = "attacker"
        else:
            by_entity.setdefault(row.entity_id, "benign")

    written = 0
    for entity_id, label in by_entity.items():
        exists = connection.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_id = ?",
            [entity_id],
        ).fetchone()
        if not exists or int(exists[0]) == 0:
            continue
        connection.execute(
            """
            UPDATE entities
            SET label = ?
            WHERE entity_id = ?
            """,
            [label, entity_id],
        )
        written += 1
    return written


def _render_metrics_markdown(
    payload: dict[str, Any],
    cold_start_table: list[dict[str, Any]],
) -> str:
    lines = [
        "# Evaluation metrics",
        "",
        f"- overlap_rule: `{payload['overlap_rule']}`",
        f"- labels_path: `{payload['labels_path']}`",
        "",
        "| detector | tp | fp | fn | precision | recall | entity_recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, metrics in payload["detectors"].items():
        lines.append(
            "| {name} | {tp} | {fp} | {fn} | {precision} | {recall} | {entity_recall} |".format(
                name=name,
                tp=metrics["tp"],
                fp=metrics["fp"],
                fn=metrics["fn"],
                precision=_fmt_optional(metrics["precision"]),
                recall=_fmt_optional(metrics["recall"]),
                entity_recall=_fmt_optional(metrics["entity_recall"]),
            )
        )
    lines.extend(["", "## Notes"])
    for note in payload.get("notes", []):
        lines.append(f"- {note}")
    if cold_start_table:
        lines.extend(
            [
                "",
                "## Spectral cold-start (synthetic)",
                "",
                "| history_hours | flagged_attack_window |",
                "|---:|---|",
            ]
        )
        for row in cold_start_table:
            lines.append(
                f"| {row['history_hours']} | {str(row['flagged_attack_window']).lower()} |"
            )
    lines.append("")
    return "\n".join(lines)


def _fmt_optional(value: float | None) -> str:
    if value is None:
        return "null"
    return f"{value:.4f}"


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
