package storage

// schemaSQL is the full initial schema. During active development, bump the
// schema here and recreate the DB (delete the SQLite file or redeploy with a fresh PVC)
// instead of adding versioned migrations.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS reports (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster           TEXT NOT NULL,
    namespace         TEXT NOT NULL,
    name              TEXT NOT NULL,
    report_type       TEXT NOT NULL,
    app               TEXT DEFAULT '',
    image             TEXT DEFAULT '',
    registry          TEXT DEFAULT '',
    critical_count    INTEGER DEFAULT 0,
    high_count        INTEGER DEFAULT 0,
    medium_count      INTEGER DEFAULT 0,
    low_count         INTEGER DEFAULT 0,
    unknown_count     INTEGER DEFAULT 0,
    components_count  INTEGER DEFAULT 0,
    data              TEXT NOT NULL,
    received_at       TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    notes             TEXT DEFAULT '',
    notes_created_at  TEXT,
    notes_updated_at  TEXT,
    UNIQUE(cluster, namespace, name, report_type)
);

CREATE INDEX IF NOT EXISTS idx_reports_cluster       ON reports(cluster);
CREATE INDEX IF NOT EXISTS idx_reports_namespace     ON reports(namespace);
CREATE INDEX IF NOT EXISTS idx_reports_report_type   ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_app           ON reports(app);
CREATE INDEX IF NOT EXISTS idx_reports_severity      ON reports(critical_count, high_count);
CREATE INDEX IF NOT EXISTS idx_reports_received_at   ON reports(received_at);
CREATE INDEX IF NOT EXISTS idx_reports_cluster_type_updated
    ON reports(cluster, report_type, updated_at);
CREATE INDEX IF NOT EXISTS idx_reports_type_updated
    ON reports(report_type, updated_at);

CREATE TABLE IF NOT EXISTS api_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    method        TEXT NOT NULL,
    path          TEXT NOT NULL,
    status_code   INTEGER NOT NULL,
    duration_ms   INTEGER NOT NULL,
    user_sub      TEXT DEFAULT '',
    user_email    TEXT DEFAULT '',
    remote_addr   TEXT DEFAULT '',
    user_agent    TEXT DEFAULT '',
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_logs_created_at ON api_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_api_logs_path ON api_logs(path);
CREATE INDEX IF NOT EXISTS idx_api_logs_status_code ON api_logs(status_code);

CREATE TABLE IF NOT EXISTS cleanup_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    retention_days  INTEGER NOT NULL,
    deleted_count   INTEGER NOT NULL,
    triggered_by    TEXT NOT NULL DEFAULT 'system',
    cleaned_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cleanup_history_cleaned_at ON cleanup_history(cleaned_at);

CREATE VIEW IF NOT EXISTS clusters_view AS
SELECT
    cluster,
    SUM(CASE WHEN report_type = 'vulnerabilityreport' THEN 1 ELSE 0 END) AS vuln_count,
    SUM(CASE WHEN report_type = 'sbomreport'          THEN 1 ELSE 0 END) AS sbom_count,
    MAX(updated_at) AS last_seen
FROM reports
GROUP BY cluster;
`
