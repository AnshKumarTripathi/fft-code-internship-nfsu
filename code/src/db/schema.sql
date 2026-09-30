-- ============================================================
-- Core entity registry
-- Phase 1: native DuckDB tables (CREATE IF NOT EXISTS).
-- Later phases may overlay Parquet-backed views for large facts.
-- ============================================================
CREATE TABLE IF NOT EXISTS entities (
    entity_id        VARCHAR PRIMARY KEY,
    entity_type      VARCHAR,
    first_seen       TIMESTAMP,
    last_seen        TIMESTAMP,
    label            VARCHAR
);

-- ============================================================
-- Parsing layer
-- ============================================================
CREATE TABLE IF NOT EXISTS templates (
    template_id       VARCHAR PRIMARY KEY,
    template_string    VARCHAR,
    first_seen         TIMESTAMP,
    last_seen          TIMESTAMP,
    occurrence_count    BIGINT
);

CREATE TABLE IF NOT EXISTS parsed_events (
    event_id           BIGINT PRIMARY KEY,
    entity_id           VARCHAR REFERENCES entities(entity_id),
    template_id          VARCHAR REFERENCES templates(template_id),
    event_timestamp       TIMESTAMP,
    log_source             VARCHAR,
    raw_fields              JSON,
    ingested_at              TIMESTAMP,
    parser_snapshot_id         VARCHAR
);

-- ============================================================
-- Time series layer
-- ============================================================
CREATE TABLE IF NOT EXISTS entity_bucket_counts (
    entity_id            VARCHAR REFERENCES entities(entity_id),
    bucket_start           TIMESTAMP,
    bucket_seconds           INTEGER,
    event_count               DOUBLE,
    PRIMARY KEY (entity_id, bucket_start, bucket_seconds)
);

-- ============================================================
-- Spectral (Fourier) detector layer
-- ============================================================
CREATE TABLE IF NOT EXISTS spectral_baselines (
    entity_id             VARCHAR PRIMARY KEY REFERENCES entities(entity_id),
    computed_at             TIMESTAMP,
    bucket_seconds            INTEGER,
    nperseg                    INTEGER,
    freq_grid                   DOUBLE[],
    psd                          DOUBLE[],
    psd_norm                      DOUBLE[]
);

CREATE TABLE IF NOT EXISTS entity_spectral_features (
    entity_id                 VARCHAR PRIMARY KEY REFERENCES entities(entity_id),
    dominant_period_hours       DOUBLE,
    dominant_power_frac          DOUBLE,
    spectral_entropy              DOUBLE,
    total_power                    DOUBLE,
    computed_at                    TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entity_clusters (
    entity_id       VARCHAR REFERENCES entities(entity_id),
    cluster_run_id    VARCHAR,
    cluster_id          INTEGER,
    computed_at           TIMESTAMP,
    PRIMARY KEY (entity_id, cluster_run_id)
);

CREATE TABLE IF NOT EXISTS spectral_window_scores (
    entity_id       VARCHAR REFERENCES entities(entity_id),
    window_start      TIMESTAMP,
    window_end          TIMESTAMP,
    energy_z              DOUBLE,
    shape_js_z              DOUBLE,
    flagged                  BOOLEAN,
    dominant_period_hours      DOUBLE,
    shape_top_bins               VARCHAR,
    PRIMARY KEY (entity_id, window_start)
);

-- ============================================================
-- Statistical and ML detector layers
-- ============================================================
CREATE TABLE IF NOT EXISTS statistical_window_scores (
    entity_id     VARCHAR REFERENCES entities(entity_id),
    window_start    TIMESTAMP,
    window_end        TIMESTAMP,
    rate_z               DOUBLE,
    flagged                BOOLEAN,
    PRIMARY KEY (entity_id, window_start)
);

CREATE TABLE IF NOT EXISTS changepoint_window_scores (
    entity_id     VARCHAR REFERENCES entities(entity_id),
    window_start    TIMESTAMP,
    window_end        TIMESTAMP,
    cusum_high           DOUBLE,
    cusum_low            DOUBLE,
    flagged              BOOLEAN,
    direction            VARCHAR,
    PRIMARY KEY (entity_id, window_start)
);

CREATE TABLE IF NOT EXISTS seasonal_window_scores (
    entity_id       VARCHAR REFERENCES entities(entity_id),
    window_start      TIMESTAMP,
    window_end          TIMESTAMP,
    residual_z             DOUBLE,
    residual               DOUBLE,
    seasonal_level         DOUBLE,
    flagged                BOOLEAN,
    direction              VARCHAR,
    PRIMARY KEY (entity_id, window_start)
);

CREATE TABLE IF NOT EXISTS ml_window_scores (
    entity_id     VARCHAR REFERENCES entities(entity_id),
    window_start    TIMESTAMP,
    window_end        TIMESTAMP,
    model_score          DOUBLE,
    flagged                BOOLEAN,
    model_snapshot_id        VARCHAR,
    mad_z                      DOUBLE,
    attribution_json           VARCHAR,
    PRIMARY KEY (entity_id, window_start)
);

-- ============================================================
-- Correlation layer
-- ============================================================
CREATE TABLE IF NOT EXISTS anomaly_events (
    anomaly_id         VARCHAR PRIMARY KEY,
    entity_id            VARCHAR REFERENCES entities(entity_id),
    window_start           TIMESTAMP,
    window_end               TIMESTAMP,
    source_detector             VARCHAR,
    score                          DOUBLE,
    metadata                         JSON
);

CREATE TABLE IF NOT EXISTS correlation_edges (
    edge_id           VARCHAR PRIMARY KEY,
    src_event_id        BIGINT REFERENCES parsed_events(event_id),
    dst_anomaly_id         VARCHAR REFERENCES anomaly_events(anomaly_id),
    relation_type             VARCHAR,
    session_id                   VARCHAR
);

-- ============================================================
-- Reporting layer
-- ============================================================
CREATE TABLE IF NOT EXISTS incidents (
    incident_id                 VARCHAR PRIMARY KEY,
    entity_id                     VARCHAR REFERENCES entities(entity_id),
    start_time                      TIMESTAMP,
    end_time                          TIMESTAMP,
    severity                            VARCHAR,
    summary_text                          TEXT,
    contributing_anomaly_ids                VARCHAR[]
);

-- ============================================================
-- Pipeline bookkeeping
-- ============================================================
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id         VARCHAR PRIMARY KEY,
    stage            VARCHAR,
    started_at         TIMESTAMP,
    finished_at           TIMESTAMP,
    status                  VARCHAR,
    params_json                JSON
);

-- R4: per-file SHA-256 of raw inputs for a given ingest run (bytes on disk).
CREATE TABLE IF NOT EXISTS ingest_source_files (
    run_id         VARCHAR REFERENCES pipeline_runs(run_id),
    source_path      VARCHAR,
    sha256             VARCHAR,
    size_bytes           BIGINT,
    mtime_utc              TIMESTAMP,
    PRIMARY KEY (run_id, source_path)
);

-- R6: skipped corrupt Parquet shards / loader isolation (run_id optional).
CREATE TABLE IF NOT EXISTS pipeline_errors (
    error_id       VARCHAR PRIMARY KEY,
    run_id           VARCHAR,
    stage              VARCHAR,
    source_path          VARCHAR,
    error_class            VARCHAR,
    message                  VARCHAR,
    recorded_at                TIMESTAMP
);

-- R9: append-only analyst audit trail. No FK so correlate DELETE FROM incidents
-- cannot drop history. Undo is a compensating ``reopen`` row, never UPDATE/DELETE.
CREATE TABLE IF NOT EXISTS analyst_actions (
    action_id        VARCHAR PRIMARY KEY,
    incident_id      VARCHAR NOT NULL,
    anomaly_id       VARCHAR,
    action           VARCHAR NOT NULL,
    note             VARCHAR,
    operator_label   VARCHAR NOT NULL,
    created_at       TIMESTAMP NOT NULL,
    run_id           VARCHAR
);

-- Phase 65: named analysis containers (corpus + job binding). Live warehouse
-- triage remains single-writer; history snapshots arrive in Phase 66.
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id       VARCHAR PRIMARY KEY,
    label             VARCHAR NOT NULL,
    created_at        TIMESTAMP NOT NULL,
    updated_at        TIMESTAMP,
    status            VARCHAR NOT NULL,
    corpus_digest     VARCHAR,
    file_count        INTEGER,
    job_id            VARCHAR,
    correlate_run_id  VARCHAR,
    notes             VARCHAR
);
