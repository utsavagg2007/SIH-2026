-- SIH26-26145 alert store
--
-- Paste into the Supabase SQL editor, or run against any Postgres:
--     psql "$DATABASE_URL" -f db/schema.sql
--
-- Design notes:
--   * Timestamps are stored as double precision Unix epoch seconds, not
--     timestamptz. The build plan freezes "time is always a Unix float in UTC,
--     no local time anywhere, ever", and keeping one representation end to end
--     removes a whole class of timezone bug between the detector, the API and
--     the dashboard. The ISO-8601 strings the detector sent are preserved
--     verbatim inside `raw`.
--   * `evidence` is the untouched v1.1 evidence bag. `evidence_bars` is the
--     backend's projection of it. Both are stored so the projection can be
--     changed and replayed without losing what the detector actually said.
--   * Indexes cover timestamp, source IP and threat class - the three things
--     every dashboard and analyst query filters on (Downstream Architecture 8.3).

CREATE TABLE IF NOT EXISTS alerts (
    alert_id             TEXT PRIMARY KEY,
    schema_version       TEXT NOT NULL,

    -- ts mirrors detected_at; kept as its own column because every ordering
    -- and range query uses it and a dedicated index reads better than one on
    -- an aliased column.
    ts                   DOUBLE PRECISION NOT NULL,
    event_start          DOUBLE PRECISION NOT NULL,
    event_end            DOUBLE PRECISION NOT NULL,
    detected_at          DOUBLE PRECISION NOT NULL,
    ingested_at          DOUBLE PRECISION NOT NULL,

    event_scope          TEXT NOT NULL,
    flow_id              TEXT,
    src_ip               TEXT,
    dst_ip               TEXT,
    dst_port             INTEGER,
    protocol             TEXT,

    threat_class         TEXT NOT NULL,
    severity             TEXT NOT NULL,
    score                DOUBLE PRECISION NOT NULL,
    score_type           TEXT NOT NULL,

    detector             TEXT NOT NULL,
    detector_version     TEXT NOT NULL,

    incident_id          TEXT,
    kill_chain_stage     TEXT NOT NULL,

    -- Deduplication state (Build Plan layer 5).
    occurrences          INTEGER NOT NULL DEFAULT 1,
    first_seen           DOUBLE PRECISION NOT NULL,
    last_seen            DOUBLE PRECISION NOT NULL,
    dedup_key            TEXT NOT NULL,

    -- Latency accounting (Build Plan layer 6). pipeline_latency_ms is the
    -- packet-to-alert delay we are required to report.
    detector_latency_ms  DOUBLE PRECISION NOT NULL,
    transport_latency_ms DOUBLE PRECISION NOT NULL,
    pipeline_latency_ms  DOUBLE PRECISION NOT NULL,

    evidence             JSONB NOT NULL,
    evidence_bars        JSONB,
    visual               JSONB,
    mitre_techniques     TEXT[] NOT NULL DEFAULT '{}',
    raw                  JSONB NOT NULL,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT alerts_score_range CHECK (score >= 0.0 AND score <= 1.0),
    CONSTRAINT alerts_severity_enum
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT alerts_threat_class_enum CHECK (threat_class IN (
        'dga_domain', 'dns_tunnelling', 'c2_beaconing', 'encrypted_malware',
        'ddos', 'port_scan', 'data_exfiltration'
    )),
    CONSTRAINT alerts_score_type_enum CHECK (score_type IN (
        'calibrated_model', 'rule_score', 'anomaly_score', 'signature_match'
    )),
    CONSTRAINT alerts_event_scope_enum CHECK (event_scope IN (
        'flow', 'source_host', 'destination_host', 'host_pair', 'network'
    ))
);

CREATE INDEX IF NOT EXISTS alerts_ts_idx           ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS alerts_src_ip_idx       ON alerts (src_ip) WHERE src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_dst_ip_idx       ON alerts (dst_ip) WHERE dst_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_threat_class_idx ON alerts (threat_class, ts DESC);
CREATE INDEX IF NOT EXISTS alerts_severity_idx     ON alerts (severity, ts DESC);
CREATE INDEX IF NOT EXISTS alerts_incident_idx     ON alerts (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS alerts_detector_idx     ON alerts (detector, ts DESC);
CREATE INDEX IF NOT EXISTS alerts_dedup_key_idx    ON alerts (dedup_key, ts DESC);

-- The dashboard filters by class and severity together far more often than by
-- either alone; one composite index serves the Live view's filter chips.
CREATE INDEX IF NOT EXISTS alerts_class_sev_ts_idx
    ON alerts (threat_class, severity, ts DESC);

-- Evidence is queried by key from the analyst layer ("which alerts mention
-- this JA3 hash"). GIN is what makes that not a sequential scan.
CREATE INDEX IF NOT EXISTS alerts_evidence_gin_idx ON alerts USING GIN (evidence);


CREATE TABLE IF NOT EXISTS incidents (
    incident_id      TEXT PRIMARY KEY,
    pivot_host       TEXT NOT NULL,
    opened_at        DOUBLE PRECISION NOT NULL,
    updated_at       DOUBLE PRECISION NOT NULL,
    severity         TEXT NOT NULL,
    confidence       DOUBLE PRECISION NOT NULL,
    -- True when the incident spans multiple kill-chain stages, which is what
    -- justifies its severity exceeding that of any single member alert.
    escalated        BOOLEAN NOT NULL DEFAULT FALSE,
    alert_count      INTEGER NOT NULL DEFAULT 0,
    stages           TEXT[] NOT NULL DEFAULT '{}',
    threat_classes   TEXT[] NOT NULL DEFAULT '{}',
    narrative        TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT incidents_severity_enum
        CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS incidents_updated_idx ON incidents (updated_at DESC);
CREATE INDEX IF NOT EXISTS incidents_host_idx    ON incidents (pivot_host, updated_at DESC);


-- Join table. An alert belongs to at most one incident, but the membership is
-- kept separately so an incident can be reconstructed without scanning alerts,
-- and so re-correlation does not have to rewrite alert rows.
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id  TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id     TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    stage        TEXT NOT NULL,
    added_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE INDEX IF NOT EXISTS incident_alerts_alert_idx ON incident_alerts (alert_id);


-- Convenience view for the Host investigation screen. Aggregating in the
-- database keeps the API from pulling every alert for a host just to count
-- them.
CREATE OR REPLACE VIEW host_summary AS
SELECT
    ip,
    MIN(first_ts)                        AS first_seen,
    MAX(last_ts)                         AS last_seen,
    SUM(n)::BIGINT                       AS alert_count
FROM (
    SELECT src_ip AS ip, MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS n
    FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip
    UNION ALL
    SELECT dst_ip AS ip, MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS n
    FROM alerts WHERE dst_ip IS NOT NULL GROUP BY dst_ip
) t
GROUP BY ip;


-- Supabase enables Row Level Security prompts on new tables. This prototype has
-- no auth layer (Frontend spec section 1.1 puts it explicitly out of scope), and
-- the service connects with the Postgres role directly rather than through
-- PostgREST, so RLS is left off. Turning it on is the first thing to do if this
-- is ever exposed beyond the enclave.
--
--   ALTER TABLE alerts    ENABLE ROW LEVEL SECURITY;
--   ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
