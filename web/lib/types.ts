export type ListEnvelope<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
};

export type IncidentKpis = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_correlate_at: string | null;
  last_report_at?: string | null;
  detector_counts?: Record<string, number>;
  log_source_counts?: { log_source: string; count: number }[];
};

export type AnalystActionItem = {
  action_id: string;
  incident_id: string;
  anomaly_id: string | null;
  action: string;
  note: string | null;
  operator_label: string;
  created_at: string | null;
  run_id: string | null;
};

export type AnalystActionCreate = {
  incident_id: string;
  anomaly_id?: string | null;
  action: "dismiss" | "note" | "reopen";
  note?: string | null;
  operator_label?: string | null;
  run_id?: string | null;
};

export type UiHonestyPolicy = {
  warn_band: number;
  statistical_z_threshold: number;
  spectral_z_threshold: number;
  ml_mad_k: number;
  operator_label: string;
};

export type IncidentItem = {
  incident_id: string;
  entity_id: string;
  start_time: string | null;
  end_time: string | null;
  severity: string;
  summary_text: string | null;
  contributing_anomaly_ids: string[];
  detector_set?: string[];
  anomaly_count?: number;
};

export type UncertaintyHint = {
  z: number | null;
  threshold: number | null;
  warn_band: number | null;
  band: string;
  display: string;
};

export type PlaybookHint = {
  title: string;
  hint: string;
  actions: string[];
};

export type AnomalyExplanation = {
  detector: string;
  entity_id: string;
  window_start: string | null;
  window_end: string | null;
  bucket_seconds: number | null;
  headline: string;
  log_sources: { log_source: string; event_count: number }[];
  gap: {
    bucket_count?: number | null;
    zero_bucket_count?: number | null;
    zero_fraction?: number | null;
    possible_gap?: boolean | null;
  } | null;
  playbook: PlaybookHint | null;
  uncertainty: UncertaintyHint | null;
  statistical: {
    rate_z: number | null;
    z_threshold: number | null;
    rule: string;
  } | null;
  spectral: {
    energy_z: number | null;
    shape_js_z: number | null;
    crossing_legs: string[];
    rule: string;
    z_threshold: number | null;
    dominant_period_hours: number | null;
  } | null;
  ml: {
    model_type: string | null;
    mad_z: number | null;
    mad_k: number | null;
    model_snapshot_id: string | null;
    flagging: string | null;
    top_templates?: {
      template_id: string;
      template_string: string | null;
      event_count: number;
      contribution?: number | null;
    }[];
    top_contributing_features?: { name: string; contribution: number }[];
    ensemble?: {
      fusion?: string;
      votes?: Record<string, boolean>;
      scores?: Record<string, number>;
    } | null;
  } | null;
  cluster: {
    peer_cluster_size: number | null;
    nearest_distance: number | null;
    n_outliers: number | null;
    lookback_days: number | null;
  } | null;
  changepoint?: {
    cusum_high: number | null;
    cusum_low: number | null;
    decision_h: number | null;
    drift_k: number | null;
    direction: string | null;
    rule: string;
  } | null;
  seasonal?: {
    residual_z: number | null;
    residual: number | null;
    seasonal_level: number | null;
    z_threshold: number | null;
    period_buckets: number | null;
    direction: string | null;
    rule: string;
  } | null;
};

export type AnomalyItem = {
  anomaly_id: string;
  entity_id: string;
  window_start: string | null;
  window_end: string | null;
  source_detector: string;
  score: number;
  metadata: Record<string, unknown>;
  explanation: AnomalyExplanation;
};

export type IncidentDetail = IncidentItem & {
  anomalies: AnomalyItem[];
  edge_counts?: Record<string, number>;
  has_ip_link?: boolean;
  has_host_link?: boolean;
  top_score?: number | null;
  anomalies_total?: number;
  actions?: AnalystActionItem[];
};

export type TimelineEvent = {
  event_id: number;
  event_timestamp: string | null;
  template_id: string | null;
  template_string: string | null;
  log_source: string | null;
  raw_fields: Record<string, unknown>;
  related_anomaly_ids: string[];
};

export type IncidentTimelineEvent = {
  event_id: number | null;
  event_timestamp: string | null;
  relation_type: string;
  template_string: string | null;
  log_source: string | null;
  raw_fields: Record<string, unknown>;
  dst_anomaly_id: string;
  session_id: string | null;
  snippet: string | null;
};

export type IncidentEdgeItem = {
  edge_id: string;
  src_event_id: number | null;
  dst_anomaly_id: string;
  relation_type: string;
  session_id: string | null;
  event_timestamp: string | null;
  snippet: string | null;
  template_string: string | null;
  log_source: string | null;
  raw_fields: Record<string, unknown>;
};

export type EntityMeta = {
  entity_id: string;
  entity_type: string | null;
  first_seen: string | null;
  last_seen: string | null;
  label: string | null;
};

export type BucketPoint = {
  bucket_start: string | null;
  event_count: number;
};

export type FlaggedWindow = {
  source: string;
  window_start: string | null;
  window_end: string | null;
};

export type BucketSeriesResponse = ListEnvelope<BucketPoint> & {
  overlays: FlaggedWindow[];
  bucket_seconds: number | null;
};

export type SpectralFeatures = {
  entity_id: string;
  dominant_period_hours: number | null;
  dominant_power_frac: number | null;
  spectral_entropy: number | null;
  total_power: number | null;
  computed_at: string | null;
};

export type SpectralWindowScore = {
  window_start: string | null;
  window_end: string | null;
  energy_z: number | null;
  shape_js_z: number | null;
  flagged: boolean;
  z?: number | null;
  band?: string | null;
  display?: string | null;
};

export type SpectrumResponse = {
  entity_id: string;
  features: SpectralFeatures | null;
  freq_grid: number[];
  psd_norm: number[];
  downsampled: boolean;
  bucket_seconds: number | null;
  recent_scores: SpectralWindowScore[];
  z_threshold?: number | null;
  warn_band?: number | null;
};

export type StftMatrixResponse = {
  entity_id: string;
  bucket_seconds: number;
  window_buckets: number;
  step_buckets: number;
  freqs: number[];
  period_hours: (number | null)[];
  time_starts: (string | null)[];
  power: (number | null)[][];
  n_freq: number;
  n_time: number;
  capped: boolean;
  truncated_input: boolean;
  empty_reason: string | null;
  input_buckets: number;
  gap_fraction: number | null;
  cap_max_freq: number;
  cap_max_time: number;
};

export type PipelineRunItem = {
  run_id: string;
  stage: string;
  started_at: string | null;
  finished_at: string | null;
  status: string;
};

export type PipelineJobStageItem = {
  stage: string;
  status: string;
  detail: string | null;
  finished_at: string | null;
};

export type PipelineJobStatus = {
  job_id: string;
  status: string;
  mode: string;
  require_complete: boolean;
  current_stage: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  completed_stages: number;
  total_stages: number;
  stages: PipelineJobStageItem[];
  analysis_id?: string | null;
  ml_ensemble_enabled?: boolean | null;
  phase?: string | null;
  shard_index?: number | null;
  shard_count?: number | null;
  input_path?: string | null;
  cancel_supported?: boolean;
  cancel_requested?: boolean;
};

export type PipelineJobCreate = {
  mode?: string;
  require_complete?: boolean;
  stages?: string[] | null;
  analysis_id?: string | null;
  label?: string | null;
  notes?: string | null;
  ml_ensemble_enabled?: boolean | null;
  input_path?: string | null;
  use_staged_uploads?: boolean;
};

export type PipelineShardingSettings = {
  enabled: boolean;
  prefer_server_path: boolean;
  target_shard_bytes: number | null;
  target_shard_lines: number | null;
  max_shards: number;
  output_dir: string;
  raw_log_dir: string;
  max_upload_bytes: number;
  analysis_window_enabled?: boolean;
  analysis_window_last_days?: number;
  analysis_window_start_utc?: string | null;
  analysis_window_end_utc?: string | null;
};

export type PipelineCorpusListResponse = {
  files: PipelineUploadFileItem[];
  raw_log_dir: string;
  mode: string;
};

export type AnalysisItem = {
  analysis_id: string;
  label: string;
  status: string;
  corpus_digest: string | null;
  file_count: number | null;
  created_at: string | null;
  updated_at: string | null;
  job_id: string | null;
  correlate_run_id: string | null;
  notes: string | null;
};

export type AnalysisCreate = {
  label: string;
  notes?: string | null;
};

export type AnalysisUpdate = {
  label?: string | null;
  notes?: string | null;
};

export type PipelineUploadFileItem = {
  name: string;
  size_bytes: number;
  sha256: string;
  modified_at: string;
};

export type PipelineUploadListResponse = {
  files: PipelineUploadFileItem[];
  upload_dir: string;
};

export type PipelineLabResetRequest = {
  confirm: "CLEAR";
  clear_uploads?: boolean;
  clear_raw_non_upload?: boolean;
};

export type PipelineLabResetResponse = {
  ok: boolean;
  message: string;
  clear_uploads: boolean;
  clear_raw_non_upload: boolean;
  cleared: Record<string, string[]>;
};

export type ReportFileItem = {
  filename: string;
  incident_id: string;
  media_type: string;
};

export type CopilotAttachment = {
  kind: string;
  route?: string | null;
  incident_id?: string | null;
  entity_id?: string | null;
  label?: string | null;
  text?: string | null;
  slug?: string | null;
};

export type CopilotChatMessage = {
  role: string;
  content: string;
};

export type CopilotCitation = {
  source: string;
  ref: string;
};

export type CopilotChatResponse = {
  reply: string;
  citations: CopilotCitation[];
  tools_used: string[];
  provider: string;
  model: string;
};

export type CopilotStatus = {
  enabled: boolean;
  provider: string;
  model: string;
  reason?: string | null;
};

export type IncidentListParams = {
  severity?: string;
  entity_id?: string;
  q?: string;
  start_after?: string;
  end_before?: string;
  detector?: string;
  min_detectors?: number;
  disposition?: string;
  sort?: string;
  order?: string;
  limit?: number;
  offset?: number;
};

export type EntityListParams = {
  q?: string;
  limit?: number;
  offset?: number;
};

export type WindowQuery = {
  start?: string;
  end?: string;
  limit?: number;
  offset?: number;
  order?: string;
};
