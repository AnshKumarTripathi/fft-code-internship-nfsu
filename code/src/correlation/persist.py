"""Orchestrate Phase 8 correlate: merge → sessions → graph → persist."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Any

from src.config import ConfigError, changepoint_settings, explainability_settings, ml_settings
from src.correlation.graph_builder import (
    build_graph,
    filter_incidents_by_agreement,
)
from src.correlation.merge_scores import (
    CLUSTER_OUTLIER_POLICIES,
    DEFAULT_CLUSTER_OUTLIER_LOOKBACK_DAYS,
    DEFAULT_CLUSTER_OUTLIER_WINDOW,
    CorrelationError,
    discover_and_merge,
)
from src.explainability.payload import ExplainMergeSettings
from src.explainability.playbooks import PlaybookError, load_playbooks
from src.correlation.session_linker import link_sessions
from src.correlation.writers import (
    clear_correlation_tables,
    insert_anomaly_events,
    insert_correlation_edges,
    insert_incidents,
)
from src.db.connection import get_connection, record_run_finish, record_run_start

logger = logging.getLogger(__name__)

DEFAULT_SESSION_GAP_MINUTES = 30
DEFAULT_INCIDENT_GAP_MINUTES = 360
DEFAULT_IP_LINK_HORIZON_HOURS = 24
DEFAULT_PROMOTION_MODE = "any_flag"
DEFAULT_PROMOTION_MIN_DETECTORS = 2
PROMOTION_MODES = frozenset({"any_flag", "severity_boost", "min_detectors"})
# any_flag always uses this threshold so severity matches pre-54 behaviour.
ANY_FLAG_AGREEMENT_THRESHOLD = 2


@dataclass
class CorrelateSummary:
    sources: list[str]
    anomalies: int = 0
    sessions: int = 0
    edges: int = 0
    incidents: int = 0
    degraded_no_events: bool = False
    severity_counts: dict[str, int] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CorrelationSettings:
    session_gap_minutes: int
    same_ip_link: bool
    same_host_link: bool
    incident_gap_minutes: int
    cluster_outlier_window: str
    cluster_outlier_lookback_days: int
    ip_link_horizon_hours: int
    promotion_mode: str = DEFAULT_PROMOTION_MODE
    promotion_min_detectors: int = DEFAULT_PROMOTION_MIN_DETECTORS

    @property
    def agreement_threshold(self) -> int:
        """Threshold passed to compute_severity for multi-detector high/critical."""
        if self.promotion_mode == "any_flag":
            return ANY_FLAG_AGREEMENT_THRESHOLD
        return self.promotion_min_detectors


def _positive_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CorrelationError(
            f"correlation.{key} must be a positive integer, got {value!r}"
        )
    return value


def _validate_correlation_config(config: dict[str, Any]) -> CorrelationSettings:
    corr = config.get("correlation") or {}
    policy = corr.get("cluster_outlier_window", DEFAULT_CLUSTER_OUTLIER_WINDOW)
    if policy not in CLUSTER_OUTLIER_POLICIES:
        raise CorrelationError(
            f"correlation.cluster_outlier_window must be one of "
            f"{sorted(CLUSTER_OUTLIER_POLICIES)}, got {policy!r}"
        )
    promotion = corr.get("promotion") or {}
    if not isinstance(promotion, dict):
        raise CorrelationError(
            f"correlation.promotion must be a mapping, got {type(promotion).__name__}"
        )
    mode = str(promotion.get("mode", DEFAULT_PROMOTION_MODE))
    if mode not in PROMOTION_MODES:
        raise CorrelationError(
            f"correlation.promotion.mode must be one of "
            f"{sorted(PROMOTION_MODES)}, got {mode!r}"
        )
    return CorrelationSettings(
        session_gap_minutes=_positive_int(
            corr.get("session_gap_minutes", DEFAULT_SESSION_GAP_MINUTES),
            "session_gap_minutes",
        ),
        same_ip_link=bool(corr.get("same_ip_link", True)),
        same_host_link=bool(corr.get("same_host_link", True)),
        incident_gap_minutes=_positive_int(
            corr.get("incident_gap_minutes", DEFAULT_INCIDENT_GAP_MINUTES),
            "incident_gap_minutes",
        ),
        cluster_outlier_window=str(policy),
        cluster_outlier_lookback_days=_positive_int(
            corr.get(
                "cluster_outlier_lookback_days",
                DEFAULT_CLUSTER_OUTLIER_LOOKBACK_DAYS,
            ),
            "cluster_outlier_lookback_days",
        ),
        ip_link_horizon_hours=_positive_int(
            corr.get("ip_link_horizon_hours", DEFAULT_IP_LINK_HORIZON_HOURS),
            "ip_link_horizon_hours",
        ),
        promotion_mode=mode,
        promotion_min_detectors=_positive_int(
            promotion.get("min_detectors", DEFAULT_PROMOTION_MIN_DETECTORS),
            "promotion.min_detectors",
        ),
    )


def _load_entity_types(connection: Any, entity_ids: list[str]) -> dict[str, str]:
    if not entity_ids:
        return {}
    unique = sorted(set(entity_ids))
    placeholders = ", ".join("?" for _ in unique)
    rows = connection.execute(
        f"""
        SELECT entity_id, entity_type
        FROM entities
        WHERE entity_id IN ({placeholders})
        """,
        list(unique),
    ).fetchall()
    return {str(eid): str(etype) for eid, etype in rows if etype is not None}


def run_correlate(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
) -> CorrelateSummary:
    """Merge available detector outputs into anomaly_events / edges / incidents."""
    connection = get_connection(config)
    run_id: str | None = None
    try:
        settings = _validate_correlation_config(config)
        try:
            ml = ml_settings(config)
        except ConfigError as exc:
            raise CorrelationError(str(exc)) from exc
        ensemble = ml.get("ensemble") or {}
        if bool(ensemble.get("enabled")):
            ml_model_type = "ensemble"
        else:
            ml_model_type = str(ml.get("model_type", "isolation_forest"))
        ml_flagging = str(ml.get("flagging", "mad_threshold"))
        try:
            expl = explainability_settings(config)
            playbooks = load_playbooks(expl["playbooks_path"])
        except (ConfigError, PlaybookError) as exc:
            raise CorrelationError(str(exc)) from exc
        statistical = config.get("statistical") or {}
        bucketing = config.get("bucketing") or {}
        try:
            from src.config import spectral_flagging_settings

            spectral_flags = spectral_flagging_settings(config)
            cp_settings = changepoint_settings(config)
            from src.config import seasonal_settings

            seasonal_cfg = seasonal_settings(config)
        except ConfigError as exc:
            raise CorrelationError(str(exc)) from exc
        explain = ExplainMergeSettings(
            statistical_z_threshold=float(statistical.get("z_threshold", 4.0)),
            spectral_z_threshold=float(spectral_flags["z_threshold"]),
            spectral_energy_z_threshold=float(spectral_flags["energy_z_threshold"]),
            spectral_shape_js_z_threshold=float(
                spectral_flags["shape_js_z_threshold"]
            ),
            spectral_flag_mode=str(spectral_flags["flag_mode"]),
            spectral_rule=str(spectral_flags["rule"]),
            bucket_seconds=int(bucketing.get("bucket_seconds", 600)),
            ml_mad_k=float(ml.get("mad_k", 4.0)),
            changepoint_decision_h=float(cp_settings["decision_h"]),
            changepoint_drift_k=float(cp_settings["drift_k"]),
            seasonal_z_threshold=float(seasonal_cfg["z_threshold"]),
            seasonal_period_buckets=int(seasonal_cfg["period_buckets"]),
            log_source_limit=int(expl["log_source_limit"]),
            ml_top_templates=int(expl["ml_top_templates"]),
            gap_zero_fraction=float(expl["gap_zero_fraction"]),
            playbooks=playbooks,
        )
        params = {
            "config_path": config_path,
            "session_gap_minutes": settings.session_gap_minutes,
            "same_ip_link": settings.same_ip_link,
            "same_host_link": settings.same_host_link,
            "incident_gap_minutes": settings.incident_gap_minutes,
            "cluster_outlier_window": settings.cluster_outlier_window,
            "cluster_outlier_lookback_days": settings.cluster_outlier_lookback_days,
            "ip_link_horizon_hours": settings.ip_link_horizon_hours,
            "promotion_mode": settings.promotion_mode,
            "promotion_min_detectors": settings.promotion_min_detectors,
            "ml_model_type": ml_model_type,
            "ml_flagging": ml_flagging,
        }
        run_id = record_run_start(connection, stage="correlate", params=params)

        merge = discover_and_merge(
            connection,
            ml_model_type=ml_model_type,
            ml_flagging=ml_flagging,
            cluster_outlier_window=settings.cluster_outlier_window,
            cluster_outlier_lookback_days=settings.cluster_outlier_lookback_days,
            explain=explain,
        )
        clear_correlation_tables(connection)

        link = link_sessions(
            connection,
            merge.anomalies,
            session_gap_minutes=settings.session_gap_minutes,
        )
        degraded = len(link.events) == 0
        if degraded:
            logger.warning(
                "correlate: no parsed_events for anomalous entities; "
                "writing anomalies/incidents without edges"
            )

        entity_types = _load_entity_types(
            connection, [a.entity_id for a in merge.anomalies]
        )
        graph = build_graph(
            merge.anomalies,
            link,
            same_ip_link=settings.same_ip_link,
            same_host_link=settings.same_host_link,
            entity_types=entity_types,
            incident_gap_minutes=settings.incident_gap_minutes,
            ip_link_horizon_hours=settings.ip_link_horizon_hours,
            agreement_threshold=settings.agreement_threshold,
        )

        incidents = list(graph.incidents)
        if settings.promotion_mode == "min_detectors":
            before = len(incidents)
            incidents = filter_incidents_by_agreement(
                incidents,
                merge.anomalies,
                settings.promotion_min_detectors,
            )
            dropped = before - len(incidents)
            if dropped:
                logger.info(
                    "correlate promotion min_detectors=%d: dropped %d incidents",
                    settings.promotion_min_detectors,
                    dropped,
                )

        n_anomalies = insert_anomaly_events(connection, merge.anomalies)
        n_edges = insert_correlation_edges(connection, graph.edges)
        n_incidents = insert_incidents(connection, incidents)

        severity_counts: dict[str, int] = {}
        for incident in incidents:
            severity_counts[incident.severity] = (
                severity_counts.get(incident.severity, 0) + 1
            )

        summary = CorrelateSummary(
            sources=list(merge.discovered_sources),
            anomalies=n_anomalies,
            sessions=len(link.sessions),
            edges=n_edges,
            incidents=n_incidents,
            degraded_no_events=degraded,
            severity_counts=severity_counts,
        )

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

        logger.info("correlate summary: %s", summary.as_dict())
        print("correlate summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except CorrelationError:
        if run_id is not None:
            record_run_finish(connection, run_id, "failed")
        raise
    except Exception:
        if run_id is not None:
            record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()
