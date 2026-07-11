package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

// Search queries expand the stored report JSON with SQLite's JSON1 json_each
// (mirroring the upstream implementation) instead of scanning rows in Go.
//
// Load-bearing details, pinned by the API characterization tests:
//   - json_valid guards every json_each: a single malformed data row must be
//     skipped, not fail the whole query ('{}' expands to zero rows because
//     the path below it does not exist).
//   - Matching is a case-insensitive substring: instr(lower(field), q) with q
//     lowered in Go. SQLite lower() is ASCII-only, which covers the domain
//     (CVE ids, package and image names).
//   - limit <= 0 becomes SQL LIMIT -1 (no limit), matching the old in-Go
//     pagination that treated non-positive limits as "everything".

const vulnSearchFrom = `
	FROM reports r,
	     json_each(CASE WHEN json_valid(r.data) THEN r.data ELSE '{}' END,
	               '$.report.vulnerabilities') v
	WHERE r.report_type = ?
	  AND (?2 = ''
	       OR instr(lower(coalesce(json_extract(v.value, '$.vulnerabilityID'), '')), ?2) > 0
	       OR instr(lower(coalesce(json_extract(v.value, '$.title'), '')), ?2) > 0
	       OR instr(lower(coalesce(json_extract(v.value, '$.resource'), '')), ?2) > 0
	       OR instr(lower(r.app), ?2) > 0
	       OR instr(lower(r.image), ?2) > 0)`

// SearchVulnerabilities returns vulnerability rows matching q (already
// lowercased; empty matches all) plus the pre-pagination total.
func (r *ReportStore) SearchVulnerabilities(ctx context.Context, q string, limit, offset int) ([]model.VulnSearchResult, int64, error) {
	var total int64
	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*)`+vulnSearchFrom, model.ReportTypeVuln, q).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count vulnerability search: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT r.cluster, r.namespace, r.name, r.app, r.image,
		       coalesce(json_extract(v.value, '$.vulnerabilityID'), ''),
		       coalesce(json_extract(v.value, '$.severity'), ''),
		       json_extract(v.value, '$.score'),
		       coalesce(json_extract(v.value, '$.resource'), ''),
		       coalesce(json_extract(v.value, '$.installedVersion'), ''),
		       coalesce(json_extract(v.value, '$.fixedVersion'), ''),
		       r.updated_at`+vulnSearchFrom+`
		ORDER BY r.updated_at DESC, r.id, v.id
		LIMIT ? OFFSET ?`,
		model.ReportTypeVuln, q, sqlLimit(limit), max(offset, 0))
	if err != nil {
		return nil, 0, fmt.Errorf("search vulnerabilities: %w", err)
	}
	defer rows.Close()

	out := []model.VulnSearchResult{}
	for rows.Next() {
		var item model.VulnSearchResult
		var score sql.NullFloat64
		if err := rows.Scan(
			&item.Cluster, &item.Namespace, &item.Name, &item.App, &item.Image,
			&item.VulnerabilityID, &item.Severity, &score,
			&item.Resource, &item.InstalledVersion, &item.FixedVersion, &item.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan vulnerability search row: %w", err)
		}
		if score.Valid {
			item.Score = &score.Float64
		}
		out = append(out, item)
	}
	return out, total, rows.Err()
}

// SuggestVulnerabilityIDs returns distinct, sorted vulnerability ids matching
// q (already lowercased), capped at limit.
func (r *ReportStore) SuggestVulnerabilityIDs(ctx context.Context, q string, limit int) ([]string, error) {
	return r.suggest(ctx, `
		SELECT DISTINCT json_extract(v.value, '$.vulnerabilityID') AS sug
		FROM reports r,
		     json_each(CASE WHEN json_valid(r.data) THEN r.data ELSE '{}' END,
		               '$.report.vulnerabilities') v
		WHERE r.report_type = ?
		  AND coalesce(json_extract(v.value, '$.vulnerabilityID'), '') <> ''
		  AND (?2 = '' OR instr(lower(json_extract(v.value, '$.vulnerabilityID')), ?2) > 0)
		ORDER BY sug
		LIMIT ?`,
		model.ReportTypeVuln, q, limit)
}

const componentSearchFrom = `
	FROM reports r,
	     json_each(CASE WHEN json_valid(r.data) THEN r.data ELSE '{}' END,
	               '$.report.components.components') c
	WHERE r.report_type = ?
	  AND (?2 = '' OR instr(lower(coalesce(json_extract(c.value, '$.name'), '')), ?2) > 0)`

// SearchComponents returns SBOM component rows whose name matches q (already
// lowercased; empty matches all) plus the pre-pagination total.
func (r *ReportStore) SearchComponents(ctx context.Context, q string, limit, offset int) ([]model.ComponentSearchResult, int64, error) {
	var total int64
	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*)`+componentSearchFrom, model.ReportTypeSbom, q).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count component search: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT r.cluster, r.namespace, r.name, r.app, r.image,
		       coalesce(json_extract(c.value, '$.name'), ''),
		       coalesce(json_extract(c.value, '$.version'), ''),
		       coalesce(json_extract(c.value, '$.type'), ''),
		       r.updated_at`+componentSearchFrom+`
		ORDER BY r.updated_at DESC, r.id, c.id
		LIMIT ? OFFSET ?`,
		model.ReportTypeSbom, q, sqlLimit(limit), max(offset, 0))
	if err != nil {
		return nil, 0, fmt.Errorf("search components: %w", err)
	}
	defer rows.Close()

	out := []model.ComponentSearchResult{}
	for rows.Next() {
		var item model.ComponentSearchResult
		if err := rows.Scan(
			&item.Cluster, &item.Namespace, &item.Name, &item.App, &item.Image,
			&item.ComponentName, &item.ComponentVersion, &item.ComponentType, &item.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan component search row: %w", err)
		}
		out = append(out, item)
	}
	return out, total, rows.Err()
}

// SuggestComponents returns distinct, sorted component names matching q
// (already lowercased), capped at limit.
func (r *ReportStore) SuggestComponents(ctx context.Context, q string, limit int) ([]string, error) {
	return r.suggest(ctx, `
		SELECT DISTINCT json_extract(c.value, '$.name') AS sug
		FROM reports r,
		     json_each(CASE WHEN json_valid(r.data) THEN r.data ELSE '{}' END,
		               '$.report.components.components') c
		WHERE r.report_type = ?
		  AND coalesce(json_extract(c.value, '$.name'), '') <> ''
		  AND (?2 = '' OR instr(lower(json_extract(c.value, '$.name')), ?2) > 0)
		ORDER BY sug
		LIMIT ?`,
		model.ReportTypeSbom, q, limit)
}

func (r *ReportStore) suggest(ctx context.Context, query, reportType, q string, limit int) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, query, reportType, q, sqlLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("suggest: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan suggestion: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// sqlLimit maps "no limit" (non-positive) onto SQLite's LIMIT -1.
func sqlLimit(limit int) int {
	if limit <= 0 {
		return -1
	}
	return limit
}
