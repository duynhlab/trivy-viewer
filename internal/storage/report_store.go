package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

// ErrNotFound is returned when a report does not exist.
var ErrNotFound = errors.New("report not found")

// ReportStore provides typed access to the reports table and clusters_view.
type ReportStore struct {
	db *sql.DB
}

// NewReportStore builds a report store over the given database.
func NewReportStore(db *DB) *ReportStore { return &ReportStore{db: db.sql} }

const upsertSQL = `
INSERT INTO reports (
    cluster, namespace, name, report_type, app, image, registry,
    critical_count, high_count, medium_count, low_count, unknown_count,
    components_count, data, received_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cluster, namespace, name, report_type) DO UPDATE SET
    app              = excluded.app,
    image            = excluded.image,
    registry         = excluded.registry,
    critical_count   = excluded.critical_count,
    high_count       = excluded.high_count,
    medium_count     = excluded.medium_count,
    low_count        = excluded.low_count,
    unknown_count    = excluded.unknown_count,
    components_count = excluded.components_count,
    data             = excluded.data,
    updated_at       = excluded.updated_at;
`

// UpsertReport inserts a report or updates it on the natural key. User notes are
// intentionally preserved across updates (the watcher never overwrites notes).
func (r *ReportStore) UpsertReport(ctx context.Context, rep model.Report) error {
	now := time.Now().UTC().Format(time.RFC3339)
	received := rep.ReceivedAt
	if received == "" {
		received = now
	}
	updated := rep.UpdatedAt
	if updated == "" {
		updated = now
	}
	_, err := r.db.ExecContext(ctx, upsertSQL,
		rep.Cluster, rep.Namespace, rep.Name, rep.ReportType, rep.App, rep.Image, rep.Registry,
		rep.Critical, rep.High, rep.Medium, rep.Low, rep.Unknown,
		rep.ComponentsCount, rep.Data, received, updated,
	)
	if err != nil {
		return fmt.Errorf("upsert report %s/%s/%s: %w", rep.Cluster, rep.Namespace, rep.Name, err)
	}
	return nil
}

const selectCols = `
	cluster, namespace, name, report_type, app, image, registry,
	critical_count, high_count, medium_count, low_count, unknown_count,
	components_count, data, received_at, updated_at,
	notes, notes_created_at, notes_updated_at`

func scanReport(s interface{ Scan(...any) error }) (model.Report, error) {
	var rep model.Report
	err := s.Scan(
		&rep.Cluster, &rep.Namespace, &rep.Name, &rep.ReportType, &rep.App, &rep.Image, &rep.Registry,
		&rep.Critical, &rep.High, &rep.Medium, &rep.Low, &rep.Unknown,
		&rep.ComponentsCount, &rep.Data, &rep.ReceivedAt, &rep.UpdatedAt,
		&rep.Notes, &rep.NotesCreatedAt, &rep.NotesUpdatedAt,
	)
	return rep, err
}

// GetReport fetches a single report by natural key.
func (r *ReportStore) GetReport(ctx context.Context, cluster, namespace, name, reportType string) (model.Report, error) {
	q := `SELECT` + selectCols + `
		FROM reports
		WHERE cluster = ? AND namespace = ? AND name = ? AND report_type = ?`
	rep, err := scanReport(r.db.QueryRowContext(ctx, q, cluster, namespace, name, reportType))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Report{}, ErrNotFound
	}
	if err != nil {
		return model.Report{}, fmt.Errorf("get report: %w", err)
	}
	return rep, nil
}

func buildWhere(f model.Filters, reportType string) (string, []any) {
	clauses := []string{"report_type = ?"}
	args := []any{reportType}
	if f.Cluster != "" {
		clauses = append(clauses, "cluster = ?")
		args = append(args, f.Cluster)
	}
	if f.Namespace != "" {
		clauses = append(clauses, "namespace = ?")
		args = append(args, f.Namespace)
	}
	if f.App != "" {
		clauses = append(clauses, "app = ?")
		args = append(args, f.App)
	}
	if f.Component != "" {
		// Component filter searches the stored JSON; adequate for MVP list views.
		clauses = append(clauses, "data LIKE ?")
		args = append(args, "%"+f.Component+"%")
	}
	return strings.Join(clauses, " AND "), args
}

// ListReports returns reports of a type matching filters, newest first, plus the
// total count for the same filters (ignoring limit/offset).
func (r *ReportStore) ListReports(ctx context.Context, reportType string, f model.Filters) ([]model.Report, int64, error) {
	where, args := buildWhere(f, reportType)

	var total int64
	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM reports WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count reports: %w", err)
	}

	q := `SELECT` + selectCols + ` FROM reports WHERE ` + where + ` ORDER BY updated_at DESC`
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		args = append(args, f.Limit, f.Offset)
	}
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list reports: %w", err)
	}
	defer rows.Close()

	var out []model.Report
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan report: %w", err)
		}
		out = append(out, rep)
	}
	return out, total, rows.Err()
}

// ListClusters returns the per-cluster counts from the clusters view.
func (r *ReportStore) ListClusters(ctx context.Context) ([]model.ClusterInfo, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT cluster, vuln_count, sbom_count FROM clusters_view ORDER BY cluster`)
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}
	defer rows.Close()

	var out []model.ClusterInfo
	for rows.Next() {
		var c model.ClusterInfo
		if err := rows.Scan(&c.Name, &c.VulnReportCount, &c.SbomReportCount); err != nil {
			return nil, fmt.Errorf("scan cluster: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListNamespaces returns distinct namespaces, optionally scoped to a cluster.
func (r *ReportStore) ListNamespaces(ctx context.Context, cluster string) ([]string, error) {
	q := `SELECT DISTINCT namespace FROM reports`
	var args []any
	if cluster != "" {
		q += ` WHERE cluster = ?`
		args = append(args, cluster)
	}
	q += ` ORDER BY namespace`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return nil, fmt.Errorf("scan namespace: %w", err)
		}
		out = append(out, ns)
	}
	return out, rows.Err()
}

// Stats returns the dashboard aggregate. A non-empty cluster narrows every
// aggregate to that cluster; empty means all clusters.
func (r *ReportStore) Stats(ctx context.Context, cluster string) (model.Stats, error) {
	var s model.Stats
	err := r.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(DISTINCT cluster) FROM reports WHERE (?1 = '' OR cluster = ?1)),
			(SELECT COUNT(*) FROM reports WHERE report_type = 'vulnerabilityreport' AND (?1 = '' OR cluster = ?1)),
			(SELECT COUNT(*) FROM reports WHERE report_type = 'sbomreport' AND (?1 = '' OR cluster = ?1)),
			COALESCE(SUM(critical_count), 0),
			COALESCE(SUM(high_count), 0),
			COALESCE(SUM(medium_count), 0),
			COALESCE(SUM(low_count), 0),
			COALESCE(SUM(unknown_count), 0)
		FROM reports WHERE report_type = 'vulnerabilityreport' AND (?1 = '' OR cluster = ?1)`,
		cluster,
	).Scan(
		&s.TotalClusters, &s.TotalVulnReports, &s.TotalSbomReports,
		&s.TotalCritical, &s.TotalHigh, &s.TotalMedium, &s.TotalLow, &s.TotalUnknown,
	)
	if err != nil {
		return model.Stats{}, fmt.Errorf("stats: %w", err)
	}
	return s, nil
}

// CountByType returns the number of stored reports of a given type (for metrics).
func (r *ReportStore) CountByType(ctx context.Context, reportType string) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM reports WHERE report_type = ?`, reportType).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count by type: %w", err)
	}
	return n, nil
}

// DeleteReport removes a single report by natural key. A missing report is not
// an error (delete is idempotent).
func (r *ReportStore) DeleteReport(ctx context.Context, cluster, namespace, name, reportType string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM reports WHERE cluster = ? AND namespace = ? AND name = ? AND report_type = ?`,
		cluster, namespace, name, reportType)
	if err != nil {
		return fmt.Errorf("delete report: %w", err)
	}
	return nil
}

// DeleteByCluster removes all reports for a cluster; returns rows deleted.
func (r *ReportStore) DeleteByCluster(ctx context.Context, cluster string) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM reports WHERE cluster = ?`, cluster)
	if err != nil {
		return 0, fmt.Errorf("delete by cluster %s: %w", cluster, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// UpdateNotes sets the notes on a report, maintaining note timestamps.
func (r *ReportStore) UpdateNotes(ctx context.Context, cluster, reportType, namespace, name, notes string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := r.db.ExecContext(ctx, `
		UPDATE reports SET
			notes = ?,
			notes_created_at = COALESCE(notes_created_at, ?),
			notes_updated_at = ?
		WHERE cluster = ? AND report_type = ? AND namespace = ? AND name = ?`,
		notes, now, now, cluster, reportType, namespace, name,
	)
	if err != nil {
		return fmt.Errorf("update notes: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
