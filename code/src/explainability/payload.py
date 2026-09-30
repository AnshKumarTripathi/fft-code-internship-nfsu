"""Build the R7 structured explanation object from anomaly columns + metadata."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from src.explainability.playbooks import DEFAULT_PLAYBOOKS, playbook_for


@dataclass(frozen=True)
class ExplainMergeSettings:
    statistical_z_threshold: float = 4.0
    spectral_z_threshold: float = 4.0
    spectral_energy_z_threshold: float | None = None
    spectral_shape_js_z_threshold: float | None = None
    spectral_flag_mode: str = "or"
    spectral_rule: str = "energy_or_shape"
    bucket_seconds: int = 600
    ml_mad_k: float = 4.0
    changepoint_decision_h: float = 5.0
    changepoint_drift_k: float = 0.5
    seasonal_z_threshold: float = 4.0
    seasonal_period_buckets: int = 144
    log_source_limit: int = 8
    ml_top_templates: int = 5
    gap_zero_fraction: float = 0.5
    playbooks: dict[str, dict[str, Any]] | None = None

    def resolved_spectral_energy_threshold(self) -> float:
        if self.spectral_energy_z_threshold is None:
            return self.spectral_z_threshold
        return float(self.spectral_energy_z_threshold)

    def resolved_spectral_shape_threshold(self) -> float:
        if self.spectral_shape_js_z_threshold is None:
            return self.spectral_z_threshold
        return float(self.spectral_shape_js_z_threshold)


def spectral_crossing_legs(
    energy_z: float | None,
    shape_js_z: float | None,
    energy_threshold: float,
    shape_threshold: float | None = None,
) -> list[str]:
    """Which spectral tests cleared their cutoffs (per-leg thresholds)."""
    shape_thr = (
        energy_threshold if shape_threshold is None else float(shape_threshold)
    )
    legs: list[str] = []
    if energy_z is not None and energy_z >= energy_threshold:
        legs.append("energy_z")
    if shape_js_z is not None and shape_js_z >= shape_thr:
        legs.append("shape_js_z")
    return legs


def json_safe(value: Any) -> Any:
    """Make detector metadata JSON-serializable (no numpy / NaN)."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return float(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return str(value)


def _finite_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return number


def _format_z(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.1f}"


def uncertainty_band(
    z: float | None,
    threshold: float | None,
    warn_band: float = 0.5,
) -> dict[str, Any]:
    """Display-only band: flagged / near_miss / below. Does not change detectors."""
    try:
        warn = float(warn_band)
    except (TypeError, ValueError):
        warn = 0.5
    if warn < 0.0:
        warn = 0.0
    if z is None:
        return {
            "z": None,
            "threshold": threshold,
            "warn_band": warn,
            "band": "unknown",
            "display": "n/a",
        }
    if threshold is None:
        return {
            "z": z,
            "threshold": None,
            "warn_band": warn,
            "band": "unknown",
            "display": _format_z(z),
        }
    if z >= threshold:
        return {
            "z": z,
            "threshold": threshold,
            "warn_band": warn,
            "band": "flagged",
            "display": f"{_format_z(z)} ≥ {_format_z(threshold)}",
        }
    if z >= threshold - warn:
        return {
            "z": z,
            "threshold": threshold,
            "warn_band": warn,
            "band": "near_miss",
            "display": f"{_format_z(z)} (near miss of {_format_z(threshold)})",
        }
    return {
        "z": z,
        "threshold": threshold,
        "warn_band": warn,
        "band": "below",
        "display": f"{_format_z(z)} < {_format_z(threshold)}",
    }


def _z_and_threshold(
    detector: str,
    score: float,
    statistical: dict[str, Any] | None,
    spectral: dict[str, Any] | None,
    ml: dict[str, Any] | None,
    changepoint: dict[str, Any] | None = None,
    seasonal: dict[str, Any] | None = None,
) -> tuple[float | None, float | None]:
    if detector == "statistical" and statistical:
        rate = statistical.get("rate_z")
        z = rate if isinstance(rate, (int, float)) and not isinstance(rate, bool) else score
        threshold = statistical.get("z_threshold")
        return float(z), (
            float(threshold)
            if isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
            else None
        )
    if detector == "spectral" and spectral:
        candidates = [
            value
            for value in (spectral.get("energy_z"), spectral.get("shape_js_z"))
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        ]
        z = max(candidates) if candidates else score
        threshold = spectral.get("z_threshold")
        return float(z), (
            float(threshold)
            if isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
            else None
        )
    if detector == "ml" and ml:
        mad_z = ml.get("mad_z")
        z = mad_z if isinstance(mad_z, (int, float)) and not isinstance(mad_z, bool) else score
        threshold = ml.get("mad_k")
        return float(z), (
            float(threshold)
            if isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
            else None
        )
    if detector == "changepoint" and changepoint:
        candidates = [
            value
            for value in (changepoint.get("cusum_high"), changepoint.get("cusum_low"))
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        ]
        z = max(candidates) if candidates else score
        threshold = changepoint.get("decision_h")
        return float(z), (
            float(threshold)
            if isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
            else None
        )
    if detector == "seasonal" and seasonal:
        residual_z = seasonal.get("residual_z")
        z = (
            residual_z
            if isinstance(residual_z, (int, float)) and not isinstance(residual_z, bool)
            else score
        )
        threshold = seasonal.get("z_threshold")
        return float(z), (
            float(threshold)
            if isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
            else None
        )
    return float(score), None


def _as_log_sources(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        source = item.get("log_source")
        if source is None or str(source) == "":
            continue
        count = item.get("event_count", 0)
        try:
            event_count = int(count)
        except (TypeError, ValueError):
            event_count = 0
        out.append({"log_source": str(source), "event_count": event_count})
    return out


def _as_gap(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    bucket_count = value.get("bucket_count")
    zero_bucket_count = value.get("zero_bucket_count")
    try:
        buckets = int(bucket_count) if bucket_count is not None else None
        zeros = int(zero_bucket_count) if zero_bucket_count is not None else None
    except (TypeError, ValueError):
        buckets, zeros = None, None
    zero_fraction = _finite_float(value.get("zero_fraction"))
    possible = value.get("possible_gap")
    possible_gap = bool(possible) if isinstance(possible, bool) else None
    if buckets is None and zeros is None and zero_fraction is None:
        return None
    return {
        "bucket_count": buckets,
        "zero_bucket_count": zeros,
        "zero_fraction": zero_fraction,
        "possible_gap": possible_gap,
    }


def _as_bins(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        import json

        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "freq": _finite_float(item.get("freq")),
                "period_hours": _finite_float(item.get("period_hours")),
                "abs_diff": _finite_float(item.get("abs_diff")),
            }
        )
    return out


def _as_templates(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        template_id = item.get("template_id")
        if template_id is None or str(template_id) == "":
            continue
        count = item.get("event_count", 0)
        try:
            event_count = int(count)
        except (TypeError, ValueError):
            event_count = 0
        template_string = item.get("template_string")
        row: dict[str, Any] = {
            "template_id": str(template_id),
            "template_string": (
                str(template_string) if template_string is not None else None
            ),
            "event_count": event_count,
        }
        contribution = item.get("contribution")
        if contribution is not None:
            parsed = _finite_float(contribution)
            if parsed is not None:
                row["contribution"] = parsed
        out.append(row)
    return out


def _as_feature_contributions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name is None or str(name) == "":
            continue
        contribution = _finite_float(item.get("contribution"))
        if contribution is None:
            continue
        out.append({"name": str(name), "contribution": contribution})
    return out


def _headline(
    detector: str,
    metadata: dict[str, Any],
    *,
    entity_id: str,
    score: float,
) -> str:
    if detector == "statistical":
        rate = _finite_float(metadata.get("rate_z"))
        threshold = _finite_float(metadata.get("z_threshold"))
        return (
            f"High event rate on {entity_id} "
            f"(rate_z={_format_z(rate)}"
            + (f" ≥ {_format_z(threshold)}" if threshold is not None else "")
            + ")."
        )
    if detector == "spectral":
        legs = metadata.get("crossing_legs")
        if not isinstance(legs, list):
            energy = _finite_float(metadata.get("energy_z"))
            shape = _finite_float(metadata.get("shape_js_z"))
            threshold = _finite_float(metadata.get("z_threshold")) or 4.0
            legs = spectral_crossing_legs(energy, shape, threshold)
        period = _finite_float(metadata.get("dominant_period_hours"))
        energy = _finite_float(metadata.get("energy_z"))
        shape = _finite_float(metadata.get("shape_js_z"))
        period_bit = (
            f"; window dominant period ~{_format_z(period)} h"
            if period is not None and period > 0
            else ""
        )
        if legs == ["energy_z"]:
            return (
                f"Spectral energy burst on {entity_id} "
                f"(energy_z={_format_z(energy)}; shape quiet){period_bit}."
            )
        if legs == ["shape_js_z"]:
            return (
                f"Spectral shape change on {entity_id} "
                f"(shape_js_z={_format_z(shape)}; energy quiet){period_bit}."
            )
        if set(str(item) for item in legs) >= {"energy_z", "shape_js_z"}:
            return (
                f"Spectral energy and shape both flagged on {entity_id} "
                f"(energy_z={_format_z(energy)}, shape_js_z={_format_z(shape)})"
                f"{period_bit}."
            )
        return f"Spectral flag on {entity_id}{period_bit}."
    if detector == "ml":
        mad_z = _finite_float(metadata.get("mad_z"))
        flagging = str(metadata.get("flagging") or "mad_threshold")
        snapshot = metadata.get("model_snapshot_id")
        snap_bit = f", snapshot {snapshot}" if snapshot else ""
        if mad_z is not None:
            return (
                f"Unusual template sequence on {entity_id} "
                f"(mad_z={_format_z(mad_z)}, flagging={flagging}{snap_bit})."
            )
        return (
            f"Unusual template sequence on {entity_id} "
            f"(model_score={_format_z(_finite_float(metadata.get('model_score')) or score)}, "
            f"flagging={flagging}{snap_bit})."
        )
    if detector == "cluster_outlier":
        lookback = metadata.get("lookback_days")
        distance = _finite_float(metadata.get("nearest_distance"))
        n_outliers = metadata.get("n_outliers")
        bits = [f"peer-group outlier on {entity_id} (DBSCAN -1)"]
        if distance is not None:
            bits.append(f"nearest scaled distance {_format_z(distance)}")
        if lookback is not None:
            bits.append(f"lookback {lookback} d")
        if n_outliers is not None:
            bits.append(f"{n_outliers} outliers in run")
        return "; ".join(bits) + "."
    if detector == "changepoint":
        direction = str(metadata.get("direction") or "shift")
        high = _finite_float(metadata.get("cusum_high"))
        low = _finite_float(metadata.get("cusum_low"))
        h = _finite_float(metadata.get("decision_h"))
        return (
            f"Volume {direction} on {entity_id} "
            f"(CUSUM high={_format_z(high)}, low={_format_z(low)}"
            + (f" ≥ {_format_z(h)}" if h is not None else "")
            + ")."
        )
    if detector == "seasonal":
        direction = str(metadata.get("direction") or "residual")
        residual_z = _finite_float(metadata.get("residual_z"))
        threshold = _finite_float(metadata.get("z_threshold"))
        return (
            f"Seasonal {direction} residual on {entity_id} "
            f"(residual_z={_format_z(residual_z)}"
            + (f" vs {_format_z(threshold)}" if threshold is not None else "")
            + ")."
        )
    return f"{detector} flag on {entity_id} (score={_format_z(_finite_float(score))})."


def explanation_from_anomaly(
    *,
    detector: str,
    entity_id: str,
    window_start: datetime | None,
    window_end: datetime | None,
    score: float,
    metadata: dict[str, Any],
    playbooks: dict[str, dict[str, Any]] | None = None,
    warn_band: float = 0.5,
) -> dict[str, Any]:
    """Structured explanation object (API + Jinja). Never raises on sparse metadata."""
    meta = metadata if isinstance(metadata, dict) else {}
    catalog = playbooks if playbooks is not None else DEFAULT_PLAYBOOKS
    stored_playbook = meta.get("playbook") if isinstance(meta.get("playbook"), dict) else None
    model_type = None
    if detector == "ml" and meta.get("model_type") is not None:
        model_type = str(meta["model_type"])
    playbook = playbook_for(
        detector,
        stored=stored_playbook,
        playbooks=catalog,
        model_type=model_type,
    )

    statistical = None
    spectral = None
    ml = None
    cluster = None
    changepoint = None
    seasonal = None
    if detector == "statistical":
        statistical = {
            "rate_z": _finite_float(meta.get("rate_z")),
            "z_threshold": _finite_float(meta.get("z_threshold")),
            "rule": str(meta.get("rule") or "rate_z >= z_threshold"),
        }
    elif detector == "spectral":
        energy = _finite_float(meta.get("energy_z"))
        shape = _finite_float(meta.get("shape_js_z"))
        threshold = _finite_float(meta.get("z_threshold"))
        legs = meta.get("crossing_legs")
        if not isinstance(legs, list):
            legs = spectral_crossing_legs(energy, shape, threshold or 4.0)
        else:
            legs = [str(item) for item in legs]
        spectral = {
            "energy_z": energy,
            "shape_js_z": shape,
            "crossing_legs": legs,
            "rule": str(meta.get("rule") or "energy_or_shape"),
            "z_threshold": threshold,
            "energy_z_threshold": _finite_float(meta.get("energy_z_threshold")),
            "shape_js_z_threshold": _finite_float(meta.get("shape_js_z_threshold")),
            "flag_mode": (
                str(meta["flag_mode"]) if meta.get("flag_mode") is not None else None
            ),
            "dominant_period_hours": _finite_float(meta.get("dominant_period_hours")),
            "shape_top_bins": _as_bins(meta.get("shape_top_bins")),
        }
    elif detector == "ml":
        ml = {
            "model_type": (
                str(meta["model_type"]) if meta.get("model_type") is not None else None
            ),
            "flagging": (
                str(meta["flagging"]) if meta.get("flagging") is not None else None
            ),
            "model_score": _finite_float(meta.get("model_score")),
            "mad_z": _finite_float(meta.get("mad_z")),
            "mad_k": _finite_float(meta.get("mad_k")),
            "model_snapshot_id": (
                str(meta["model_snapshot_id"])
                if meta.get("model_snapshot_id") is not None
                else None
            ),
            "top_templates": _as_templates(meta.get("top_templates")),
            "top_contributing_features": _as_feature_contributions(
                meta.get("top_contributing_features")
            ),
            "ensemble": (
                meta.get("ensemble")
                if isinstance(meta.get("ensemble"), dict)
                else None
            ),
        }
    elif detector == "cluster_outlier":
        cluster_id = meta.get("cluster_id")
        try:
            cluster_id_int = int(cluster_id) if cluster_id is not None else -1
        except (TypeError, ValueError):
            cluster_id_int = -1

        def _opt_int(key: str) -> int | None:
            raw = meta.get(key)
            if raw is None:
                return None
            try:
                return int(raw)
            except (TypeError, ValueError):
                return None

        cluster = {
            "cluster_run_id": (
                str(meta["cluster_run_id"])
                if meta.get("cluster_run_id") is not None
                else None
            ),
            "cluster_id": cluster_id_int,
            "n_entities": _opt_int("n_entities"),
            "n_outliers": _opt_int("n_outliers"),
            "n_clustered": _opt_int("n_clustered"),
            "n_clusters": _opt_int("n_clusters"),
            "peer_cluster_size": _opt_int("peer_cluster_size"),
            "largest_cluster_size": _opt_int("largest_cluster_size"),
            "nearest_distance": _finite_float(meta.get("nearest_distance")),
            "window_policy": (
                str(meta["window_policy"])
                if meta.get("window_policy") is not None
                else None
            ),
            "lookback_days": _opt_int("lookback_days"),
        }
    elif detector == "changepoint":
        changepoint = {
            "cusum_high": _finite_float(meta.get("cusum_high")),
            "cusum_low": _finite_float(meta.get("cusum_low")),
            "decision_h": _finite_float(meta.get("decision_h")),
            "drift_k": _finite_float(meta.get("drift_k")),
            "direction": (
                str(meta["direction"]) if meta.get("direction") is not None else None
            ),
            "rule": str(meta.get("rule") or "cusum_sigma >= decision_h"),
        }
    elif detector == "seasonal":
        seasonal = {
            "residual_z": _finite_float(meta.get("residual_z")),
            "residual": _finite_float(meta.get("residual")),
            "seasonal_level": _finite_float(meta.get("seasonal_level")),
            "z_threshold": _finite_float(meta.get("z_threshold")),
            "period_buckets": (
                int(meta["period_buckets"])
                if isinstance(meta.get("period_buckets"), (int, float))
                and not isinstance(meta.get("period_buckets"), bool)
                else None
            ),
            "direction": (
                str(meta["direction"]) if meta.get("direction") is not None else None
            ),
            "rule": str(meta.get("rule") or "|residual_z| >= z_threshold"),
        }

    bucket_seconds = meta.get("bucket_seconds")
    try:
        bucket_int = int(bucket_seconds) if bucket_seconds is not None else None
    except (TypeError, ValueError):
        bucket_int = None

    z_value, threshold = _z_and_threshold(
        detector, score, statistical, spectral, ml, changepoint, seasonal
    )
    stored_warn = _finite_float(meta.get("warn_band"))
    resolved_warn = stored_warn if stored_warn is not None else warn_band

    return {
        "detector": detector,
        "entity_id": entity_id,
        "window_start": window_start,
        "window_end": window_end,
        "bucket_seconds": bucket_int,
        "headline": _headline(
            detector, meta, entity_id=entity_id, score=score
        ),
        "log_sources": _as_log_sources(meta.get("log_sources")),
        "gap": _as_gap(meta.get("gap")),
        "playbook": playbook,
        "uncertainty": uncertainty_band(z_value, threshold, resolved_warn),
        "statistical": statistical,
        "spectral": spectral,
        "ml": ml,
        "cluster": cluster,
        "changepoint": changepoint,
        "seasonal": seasonal,
    }
