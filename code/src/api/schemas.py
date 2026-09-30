"""Pydantic response models for the read-only JSON API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

ItemT = TypeVar("ItemT")


class ListEnvelope(BaseModel, Generic[ItemT]):
    items: list[ItemT]
    total: int
    limit: int
    offset: int


class HealthResponse(BaseModel):
    status: str
    db: str


class PipelineRunItem(BaseModel):
    run_id: str
    stage: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status: str


class IncidentItem(BaseModel):
    incident_id: str
    entity_id: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    severity: str
    summary_text: str | None = None
    contributing_anomaly_ids: list[str] = Field(default_factory=list)
    detector_set: list[str] = Field(default_factory=list)
    anomaly_count: int = 0


class LogSourceContribution(BaseModel):
    log_source: str
    event_count: int = 0


class PlaybookHint(BaseModel):
    title: str
    hint: str
    actions: list[str] = Field(default_factory=list)


class UncertaintyHint(BaseModel):
    z: float | None = None
    threshold: float | None = None
    warn_band: float | None = None
    band: str = "unknown"
    display: str = "n/a"


class GapHint(BaseModel):
    bucket_count: int | None = None
    zero_bucket_count: int | None = None
    zero_fraction: float | None = None
    possible_gap: bool | None = None


class ShapeBin(BaseModel):
    freq: float | None = None
    period_hours: float | None = None
    abs_diff: float | None = None


class TemplateContribution(BaseModel):
    template_id: str
    template_string: str | None = None
    event_count: int = 0
    contribution: float | None = None


class FeatureContribution(BaseModel):
    name: str
    contribution: float


class StatisticalExplanation(BaseModel):
    rate_z: float | None = None
    z_threshold: float | None = None
    rule: str = "rate_z >= z_threshold"


class SpectralExplanation(BaseModel):
    energy_z: float | None = None
    shape_js_z: float | None = None
    crossing_legs: list[str] = Field(default_factory=list)
    rule: str = "energy_or_shape"
    z_threshold: float | None = None
    energy_z_threshold: float | None = None
    shape_js_z_threshold: float | None = None
    flag_mode: str | None = None
    dominant_period_hours: float | None = None
    shape_top_bins: list[ShapeBin] = Field(default_factory=list)


class MlExplanation(BaseModel):
    model_type: str | None = None
    flagging: str | None = None
    model_score: float | None = None
    mad_z: float | None = None
    mad_k: float | None = None
    model_snapshot_id: str | None = None
    top_templates: list[TemplateContribution] = Field(default_factory=list)
    top_contributing_features: list[FeatureContribution] = Field(default_factory=list)


class ChangepointExplanation(BaseModel):
    cusum_high: float | None = None
    cusum_low: float | None = None
    decision_h: float | None = None
    drift_k: float | None = None
    direction: str | None = None
    rule: str = "cusum_sigma >= decision_h"


class SeasonalExplanation(BaseModel):
    residual_z: float | None = None
    residual: float | None = None
    seasonal_level: float | None = None
    z_threshold: float | None = None
    period_buckets: int | None = None
    direction: str | None = None
    rule: str = "|residual_z| >= z_threshold"


class ClusterExplanation(BaseModel):
    cluster_run_id: str | None = None
    cluster_id: int | None = None
    n_entities: int | None = None
    n_outliers: int | None = None
    n_clustered: int | None = None
    n_clusters: int | None = None
    peer_cluster_size: int | None = None
    largest_cluster_size: int | None = None
    nearest_distance: float | None = None
    window_policy: str | None = None
    lookback_days: int | None = None


class AnomalyExplanation(BaseModel):
    detector: str
    entity_id: str
    window_start: datetime | None = None
    window_end: datetime | None = None
    bucket_seconds: int | None = None
    headline: str
    log_sources: list[LogSourceContribution] = Field(default_factory=list)
    gap: GapHint | None = None
    playbook: PlaybookHint | None = None
    uncertainty: UncertaintyHint | None = None
    statistical: StatisticalExplanation | None = None
    spectral: SpectralExplanation | None = None
    ml: MlExplanation | None = None
    cluster: ClusterExplanation | None = None
    changepoint: ChangepointExplanation | None = None
    seasonal: SeasonalExplanation | None = None


class AnomalyItem(BaseModel):
    anomaly_id: str
    entity_id: str
    window_start: datetime | None = None
    window_end: datetime | None = None
    source_detector: str
    score: float
    metadata: dict[str, Any] = Field(default_factory=dict)
    explanation: AnomalyExplanation


class IncidentDetail(IncidentItem):
    anomalies: list[AnomalyItem] = Field(default_factory=list)
    edge_counts: dict[str, int] = Field(default_factory=dict)
    has_ip_link: bool = False
    has_host_link: bool = False
    top_score: float | None = None
    anomalies_total: int = 0
    actions: list["AnalystActionItem"] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    event_id: int
    event_timestamp: datetime | None = None
    template_id: str | None = None
    template_string: str | None = None
    log_source: str | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    related_anomaly_ids: list[str] = Field(default_factory=list)


class IncidentTimelineEvent(BaseModel):
    event_id: int | None = None
    event_timestamp: datetime | None = None
    relation_type: str
    template_string: str | None = None
    log_source: str | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    dst_anomaly_id: str
    session_id: str | None = None
    snippet: str | None = None


class SpectralFeatures(BaseModel):
    entity_id: str
    dominant_period_hours: float | None = None
    dominant_power_frac: float | None = None
    spectral_entropy: float | None = None
    total_power: float | None = None
    computed_at: datetime | None = None


class SpectralWindowScore(BaseModel):
    window_start: datetime | None = None
    window_end: datetime | None = None
    energy_z: float | None = None
    shape_js_z: float | None = None
    flagged: bool = False
    z: float | None = None
    band: str | None = None
    display: str | None = None


class SpectrumResponse(BaseModel):
    entity_id: str
    features: SpectralFeatures | None = None
    freq_grid: list[float] = Field(default_factory=list)
    psd_norm: list[float] = Field(default_factory=list)
    downsampled: bool = False
    bucket_seconds: int | None = None
    recent_scores: list[SpectralWindowScore] = Field(default_factory=list)
    z_threshold: float | None = None
    warn_band: float | None = None


class StftMatrixResponse(BaseModel):
    entity_id: str
    bucket_seconds: int
    window_buckets: int
    step_buckets: int
    freqs: list[float] = Field(default_factory=list)
    period_hours: list[float | None] = Field(default_factory=list)
    time_starts: list[datetime | None] = Field(default_factory=list)
    power: list[list[float | None]] = Field(default_factory=list)
    n_freq: int = 0
    n_time: int = 0
    capped: bool = False
    truncated_input: bool = False
    empty_reason: str | None = None
    input_buckets: int = 0
    gap_fraction: float | None = None
    cap_max_freq: int = 128
    cap_max_time: int = 200


class EntityMeta(BaseModel):
    entity_id: str
    entity_type: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    label: str | None = None


class EntityAnomalyRank(BaseModel):
    """Entity ranked by warehouse anomaly / incident counts (copilot + /entities/top)."""

    entity_id: str
    entity_type: str | None = None
    label: str | None = None
    anomaly_count: int = 0
    incident_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class BucketPoint(BaseModel):
    bucket_start: datetime | None = None
    event_count: float = 0.0


class FlaggedWindow(BaseModel):
    source: str
    window_start: datetime | None = None
    window_end: datetime | None = None


class BucketSeriesResponse(ListEnvelope[BucketPoint]):
    overlays: list[FlaggedWindow] = Field(default_factory=list)
    bucket_seconds: int | None = None


class LogSourceCount(BaseModel):
    log_source: str
    count: int


class IncidentKpis(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    last_correlate_at: datetime | None = None
    last_report_at: datetime | None = None
    detector_counts: dict[str, int] = Field(default_factory=dict)
    log_source_counts: list[LogSourceCount] = Field(default_factory=list)


class UiHonestyPolicy(BaseModel):
    warn_band: float
    statistical_z_threshold: float
    spectral_z_threshold: float
    ml_mad_k: float
    operator_label: str = "local"


class AnalystActionItem(BaseModel):
    action_id: str
    incident_id: str
    anomaly_id: str | None = None
    action: str
    note: str | None = None
    operator_label: str
    created_at: datetime | None = None
    run_id: str | None = None


class AnalystActionCreate(BaseModel):
    incident_id: str
    anomaly_id: str | None = None
    action: str
    note: str | None = None
    operator_label: str | None = None
    run_id: str | None = None


class IncidentEdgeItem(BaseModel):
    edge_id: str
    src_event_id: int | None = None
    dst_anomaly_id: str
    relation_type: str
    session_id: str | None = None
    event_timestamp: datetime | None = None
    snippet: str | None = None
    template_string: str | None = None
    log_source: str | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)


class IncidentEdgesResult(BaseModel):
    total: int = 0
    edges: list[IncidentEdgeItem] = Field(default_factory=list)


class ReportFileItem(BaseModel):
    filename: str
    incident_id: str
    media_type: str


class PipelineJobStageItem(BaseModel):
    stage: str
    status: str
    detail: str | None = None
    finished_at: str | None = None


class PipelineJobCreate(BaseModel):
    mode: str = "run_all"
    require_complete: bool = False
    stages: list[str] | None = None
    analysis_id: str | None = None
    label: str | None = None
    notes: str | None = None
    # Opt-in IF+AE majority vote for this job only. None = use YAML default.
    ml_ensemble_enabled: bool | None = None
    # Phase 91 — sharded large-corpus mode.
    input_path: str | None = None
    use_staged_uploads: bool = False


class PipelineJobStatus(BaseModel):
    job_id: str
    status: str
    mode: str
    require_complete: bool = False
    current_stage: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    completed_stages: int = 0
    total_stages: int = 0
    stages: list[PipelineJobStageItem] = Field(default_factory=list)
    analysis_id: str | None = None
    ml_ensemble_enabled: bool | None = None
    phase: str | None = None
    shard_index: int | None = None
    shard_count: int | None = None
    input_path: str | None = None
    cancel_supported: bool = False
    cancel_requested: bool = False


class PipelineShardingSettings(BaseModel):
    enabled: bool = False
    prefer_server_path: bool = True
    target_shard_bytes: int | None = None
    target_shard_lines: int | None = None
    max_shards: int = 500
    output_dir: str = ""
    raw_log_dir: str = ""
    max_upload_bytes: int = 52_428_800
    analysis_window_enabled: bool = False
    analysis_window_last_days: int = 30
    analysis_window_start_utc: str | None = None
    analysis_window_end_utc: str | None = None


class AnalysisCreate(BaseModel):
    label: str
    notes: str | None = None


class AnalysisUpdate(BaseModel):
    label: str | None = None
    notes: str | None = None


class AnalysisItem(BaseModel):
    analysis_id: str
    label: str
    status: str
    corpus_digest: str | None = None
    file_count: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    job_id: str | None = None
    correlate_run_id: str | None = None
    notes: str | None = None


class PipelineUploadFileItem(BaseModel):
    name: str
    size_bytes: int
    sha256: str
    modified_at: str


class PipelineUploadListResponse(BaseModel):
    files: list[PipelineUploadFileItem] = Field(default_factory=list)
    upload_dir: str


class PipelineCorpusListResponse(BaseModel):
    files: list[PipelineUploadFileItem] = Field(default_factory=list)
    raw_log_dir: str
    mode: str = "existing_raw"


class PipelineLabResetRequest(BaseModel):
    """Wipe regenerable lab outputs (warehouse, scores, reports, analyses, …)."""

    clear_uploads: bool = True
    clear_raw_non_upload: bool = False
    confirm: str = Field(
        ...,
        description="Must be exactly CLEAR to proceed",
    )


class PipelineLabResetResponse(BaseModel):
    ok: bool = True
    message: str
    clear_uploads: bool
    clear_raw_non_upload: bool
    cleared: dict[str, list[str]] = Field(default_factory=dict)


# --- Phase 96 copilot chat ---


class CopilotAttachment(BaseModel):
    kind: str = "page_selection"
    route: str | None = None
    incident_id: str | None = None
    entity_id: str | None = None
    label: str | None = None
    text: str | None = None
    slug: str | None = None


class CopilotChatMessage(BaseModel):
    role: str
    content: str


class CopilotChatRequest(BaseModel):
    messages: list[CopilotChatMessage]
    attachments: list[CopilotAttachment] = Field(default_factory=list)
    incident_id: str | None = None
    analysis_id: str | None = None


class CopilotCitation(BaseModel):
    source: str
    ref: str


class CopilotChatResponse(BaseModel):
    reply: str
    citations: list[CopilotCitation] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    provider: str
    model: str


class CopilotStatusResponse(BaseModel):
    """Public availability — never includes API keys."""

    enabled: bool
    provider: str
    model: str
    reason: str | None = None
