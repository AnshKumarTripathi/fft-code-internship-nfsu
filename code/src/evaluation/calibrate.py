"""Phase 50 threshold calibration: sweep τ on stored window scores."""

from __future__ import annotations

import json
import logging
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from src.config import evaluation_settings
from src.db.connection import get_connection
from src.evaluation.labels import EvaluationError, load_labels
from src.evaluation.metrics import (
    Detection,
    DetectorMetrics,
    OverlapRule,
    score_detections,
)

logger = logging.getLogger(__name__)

DEFAULT_TAUS: tuple[float, ...] = (3.0, 3.5, 4.0, 4.5, 5.0)
DEFAULT_LABELS_RELATIVE = Path("tests/fixtures/labels/demo_eval.csv")

# Keep YAML at 4.0 unless another τ strictly improves F1 on the labeled set.
DEFAULT_THRESHOLD = 4.0


@dataclass(frozen=True)
class ScoredWindow:
    entity_id: str
    window_start: datetime
    window_end: datetime
    rate_z: float | None = None
    energy_z: float | None = None
    shape_js_z: float | None = None
    mad_z: float | None = None


@dataclass
class CalibrationSummary:
    labels_path: str = ""
    labels_loaded: int = 0
    output_json_path: str = ""
    output_md_path: str = ""
    detectors_scored: list[str] = field(default_factory=list)
    decision: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_calibration(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    labels_path: str | Path | None = None,
    taus: Sequence[float] = DEFAULT_TAUS,
    output_dir: str | Path | None = None,
) -> CalibrationSummary:
    """Re-threshold stored scores; write calibration.json + calibration.md."""
    settings = evaluation_settings(config)
    resolved_labels = _resolve_labels_path(settings, labels_path)
    if resolved_labels is None:
        raise EvaluationError(
            "labels path required: set evaluation.labels_path or pass --labels "
            f"(default fixture: {DEFAULT_LABELS_RELATIVE.as_posix()})"
        )

    labels = load_labels(resolved_labels)
    out_dir = Path(str(output_dir or settings["output_dir"]))
    out_dir.mkdir(parents=True, exist_ok=True)
    overlap_rule: OverlapRule = settings["overlap_rule"]  # type: ignore[assignment]

    connection = get_connection(config)
    summary = CalibrationSummary(
        labels_path=str(resolved_labels),
        labels_loaded=len(labels),
    )
    try:
        scored = _load_scored_windows(connection)
        if not scored:
            raise EvaluationError(
                "no statistical/spectral/ml window scores in warehouse; "
                "run detect-* stages before calibrate"
            )

        sweeps: dict[str, dict[str, Any]] = {}
        for detector, windows in scored.items():
            by_tau: dict[str, dict[str, int | float | None]] = {}
            for tau in taus:
                detections = detections_at_threshold(detector, windows, float(tau))
                metrics = score_detections(
                    labels, detections, overlap_rule=overlap_rule
                )
                by_tau[_fmt_tau(tau)] = {
                    **metrics.as_dict(),
                    "flagged_windows": len(detections),
                    "f1": _f1(metrics),
                }
            best_tau = _select_best_tau(by_tau)
            sweeps[detector] = {
                "yaml_key": _yaml_key(detector),
                "flag_rule": _flag_rule(detector),
                "best_tau_by_f1": best_tau,
                "by_tau": by_tau,
            }

        decision = _build_decision(sweeps)
        summary.decision = decision["summary"]
        summary.detectors_scored = list(sweeps)

        payload: dict[str, Any] = {
            "phase": 50,
            "method": "recompute_flags_from_stored_scores",
            "config_path": config_path,
            "labels_path": str(resolved_labels),
            "overlap_rule": overlap_rule,
            "taus": [float(t) for t in taus],
            "default_threshold": DEFAULT_THRESHOLD,
            "detectors": sweeps,
            "decision": decision,
            "notes": [
                "Flags recomputed from rate_z / energy_z|shape_js_z / mad_z; "
                "detectors were not re-run.",
                "Cluster outliers have no z cutoff and are omitted from the sweep.",
                "Combined incidents are omitted (correlate output, not a z threshold).",
                "These are heuristic cutoffs, not calibrated p-values.",
            ],
        }

        json_path = out_dir / "calibration.json"
        md_path = out_dir / "calibration.md"
        json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        md_path.write_text(_render_markdown(payload), encoding="utf-8")
        summary.output_json_path = str(json_path)
        summary.output_md_path = str(md_path)

        logger.info("calibration summary: %s", summary.as_dict())
        print("calibration summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    finally:
        connection.close()


def detections_at_threshold(
    detector: str,
    windows: Sequence[ScoredWindow],
    tau: float,
) -> list[Detection]:
    """Apply the same flag rule as the detector stage at cutoff ``tau``."""
    out: list[Detection] = []
    for window in windows:
        if not _is_flagged(detector, window, tau):
            continue
        out.append(
            Detection(
                entity_id=window.entity_id,
                window_start=window.window_start,
                window_end=window.window_end,
            )
        )
    return out


def _is_flagged(detector: str, window: ScoredWindow, tau: float) -> bool:
    if detector == "statistical":
        z = window.rate_z
        return z is not None and math.isfinite(z) and z >= tau
    if detector == "spectral":
        energy = window.energy_z
        shape = window.shape_js_z
        energy_hit = (
            energy is not None and math.isfinite(energy) and energy >= tau
        )
        shape_hit = shape is not None and math.isfinite(shape) and shape >= tau
        return energy_hit or shape_hit
    if detector == "ml":
        z = window.mad_z
        return z is not None and math.isfinite(z) and z >= tau
    raise ValueError(f"unknown detector for calibration: {detector!r}")


def _load_scored_windows(connection: Any) -> dict[str, list[ScoredWindow]]:
    result: dict[str, list[ScoredWindow]] = {}

    if _table_has_rows(connection, "statistical_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, rate_z
            FROM statistical_window_scores
            """
        ).fetchall()
        windows = []
        for entity_id, start, end, rate_z in rows:
            parsed = _row_window(entity_id, start, end)
            if parsed is None:
                continue
            eid, w_start, w_end = parsed
            windows.append(
                ScoredWindow(
                    entity_id=eid,
                    window_start=w_start,
                    window_end=w_end,
                    rate_z=_as_float(rate_z),
                )
            )
        if windows:
            result["statistical"] = windows

    if _table_has_rows(connection, "spectral_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, energy_z, shape_js_z
            FROM spectral_window_scores
            """
        ).fetchall()
        windows = []
        for entity_id, start, end, energy_z, shape_js_z in rows:
            parsed = _row_window(entity_id, start, end)
            if parsed is None:
                continue
            eid, w_start, w_end = parsed
            windows.append(
                ScoredWindow(
                    entity_id=eid,
                    window_start=w_start,
                    window_end=w_end,
                    energy_z=_as_float(energy_z),
                    shape_js_z=_as_float(shape_js_z),
                )
            )
        if windows:
            result["spectral"] = windows

    if _table_has_rows(connection, "ml_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, mad_z
            FROM ml_window_scores
            """
        ).fetchall()
        windows = []
        for entity_id, start, end, mad_z in rows:
            parsed = _row_window(entity_id, start, end)
            if parsed is None:
                continue
            eid, w_start, w_end = parsed
            windows.append(
                ScoredWindow(
                    entity_id=eid,
                    window_start=w_start,
                    window_end=w_end,
                    mad_z=_as_float(mad_z),
                )
            )
        if windows:
            result["ml"] = windows

    return result


def _row_window(
    entity_id: Any, start: Any, end: Any
) -> tuple[str, datetime, datetime] | None:
    if not isinstance(start, datetime):
        return None
    window_end = end if isinstance(end, datetime) else start
    return (
        str(entity_id),
        _ensure_utc(start),
        _ensure_utc(window_end),
    )


def _table_exists(connection: Any, table_name: str) -> bool:
    row = connection.execute(
        """
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_name = ? AND table_schema = 'main'
        """,
        [table_name],
    ).fetchone()
    return bool(row and int(row[0]) > 0)


def _table_has_rows(connection: Any, table_name: str) -> bool:
    if not _table_exists(connection, table_name):
        return False
    row = connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
    return bool(row and int(row[0]) > 0)


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _f1(metrics: DetectorMetrics) -> float | None:
    precision = metrics.precision
    recall = metrics.recall
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2.0 * precision * recall / (precision + recall)


def _fmt_tau(tau: float) -> str:
    return f"{float(tau):.1f}"


def _yaml_key(detector: str) -> str:
    return {
        "statistical": "statistical.z_threshold",
        "spectral": "spectral.z_threshold",
        "ml": "ml.mad_k",
    }[detector]


def _flag_rule(detector: str) -> str:
    return {
        "statistical": "rate_z >= tau",
        "spectral": "energy_z >= tau OR shape_js_z >= tau",
        "ml": "mad_z >= tau",
    }[detector]


def _select_best_tau(by_tau: dict[str, dict[str, int | float | None]]) -> float | None:
    """Highest F1; ties prefer DEFAULT_THRESHOLD then lower τ."""
    best = max(
        (
            (
                float(row["f1"]),
                -abs(float(key) - DEFAULT_THRESHOLD),
                -float(key),
                float(key),
            )
            for key, row in by_tau.items()
            if isinstance(row.get("f1"), (int, float))
        ),
        default=None,
    )
    return None if best is None else best[3]


def _build_decision(sweeps: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Record keep-vs-change for YAML defaults (Phase 50 done-when)."""
    per_detector: dict[str, Any] = {}
    meaningful_change = False
    for detector, block in sweeps.items():
        best = block.get("best_tau_by_f1")
        by_tau = block["by_tau"]
        keep = best is None or abs(float(best) - DEFAULT_THRESHOLD) < 1e-9
        reason = "matches_default"
        if not keep:
            best_row = by_tau[_fmt_tau(best)]
            default_row = by_tau.get(_fmt_tau(DEFAULT_THRESHOLD), {})
            best_f1 = best_row.get("f1")
            default_f1 = default_row.get("f1")
            best_precision = best_row.get("precision")
            # Require a clear F1 gain and non-collapsed precision before
                # treating a non-4.0 cutoff as actionable on sparse demo labels.
            clear_gain = (
                isinstance(best_f1, (int, float))
                and isinstance(default_f1, (int, float))
                and best_f1 >= default_f1 + 0.05
            )
            usable_precision = (
                isinstance(best_precision, (int, float)) and best_precision >= 0.2
            )
            if clear_gain and usable_precision:
                keep = False
                meaningful_change = True
                reason = "higher_f1_with_usable_precision"
            else:
                keep = True
                reason = "f1_gain_too_small_or_precision_collapsed"
        per_detector[detector] = {
            "yaml_key": block["yaml_key"],
            "best_tau_by_f1": best,
            "keep_default_4_0": keep,
            "reason": reason,
        }

    if meaningful_change:
        summary = (
            "Measured F1 prefers a non-4.0 cutoff on at least one detector with "
            "usable precision; review calibration.md before changing YAML. "
            "Defaults left at 4.0 until an operator explicitly updates pipeline.yaml."
        )
        action = "review_before_changing_yaml"
    else:
        summary = (
            "Keep statistical.z_threshold, spectral.z_threshold, and ml.mad_k at "
            "4.0. Demo/synthetic labels are sparse; small F1 wiggles (especially "
            "with collapsed precision) do not justify changing the lab default. "
            "Measured P/R at each tau are in this artifact."
        )
        action = "keep_defaults_4_0"

    return {
        "action": action,
        "summary": summary,
        "yaml_defaults_unchanged": True,
        "per_detector": per_detector,
    }


def _resolve_labels_path(
    settings: dict[str, Any],
    labels_path: str | Path | None,
) -> Path | None:
    if labels_path is not None:
        return Path(labels_path)
    configured = settings.get("labels_path")
    if configured:
        return Path(str(configured))
    # Prefer demo_eval when running from code/
    candidate = Path.cwd() / DEFAULT_LABELS_RELATIVE
    if candidate.is_file():
        return candidate
    return None


def _render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Threshold calibration (Phase 50)",
        "",
        f"- method: `{payload['method']}`",
        f"- labels_path: `{payload['labels_path']}`",
        f"- overlap_rule: `{payload['overlap_rule']}`",
        f"- taus: `{payload['taus']}`",
        f"- default_threshold: `{payload['default_threshold']}`",
        "",
        "## Decision",
        "",
        payload["decision"]["summary"],
        "",
        f"- action: `{payload['decision']['action']}`",
        f"- yaml_defaults_unchanged: `{payload['decision']['yaml_defaults_unchanged']}`",
        "",
    ]
    for detector, block in payload["detectors"].items():
        lines.extend(
            [
                f"## {detector}",
                "",
                f"- yaml_key: `{block['yaml_key']}`",
                f"- flag_rule: `{block['flag_rule']}`",
                f"- best_tau_by_f1: `{block['best_tau_by_f1']}`",
                "",
                "| tau | tp | fp | fn | precision | recall | f1 | flagged_windows |",
                "|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for tau_key in sorted(block["by_tau"].keys(), key=float):
            row = block["by_tau"][tau_key]
            lines.append(
                "| {tau} | {tp} | {fp} | {fn} | {precision} | {recall} | {f1} | {flagged} |".format(
                    tau=tau_key,
                    tp=row["tp"],
                    fp=row["fp"],
                    fn=row["fn"],
                    precision=_fmt_optional(row["precision"]),
                    recall=_fmt_optional(row["recall"]),
                    f1=_fmt_optional(row["f1"]),
                    flagged=row["flagged_windows"],
                )
            )
        lines.append("")

    lines.extend(["## Notes"])
    for note in payload.get("notes", []):
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def _fmt_optional(value: float | None) -> str:
    if value is None:
        return "null"
    return f"{float(value):.4f}"


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
