package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

// InsertAPILog records one HTTP request for the audit UI.
func (r *Repository) InsertAPILog(ctx context.Context, entry model.APILogEntry) error {
	created := entry.CreatedAt
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO api_logs (
			method, path, status_code, duration_ms,
			user_sub, user_email, remote_addr, user_agent, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Method, entry.Path, entry.StatusCode, entry.DurationMS,
		entry.UserSub, entry.UserEmail, entry.RemoteAddr, entry.UserAgent, created,
	)
	if err != nil {
		return fmt.Errorf("insert api log: %w", err)
	}
	return nil
}

// ListAPILogs returns audit rows newest-first with optional filters.
func (r *Repository) ListAPILogs(ctx context.Context, f model.APILogFilters) ([]model.APILogEntry, int64, error) {
	where, args := apiLogWhere(f)
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	countSQL := `SELECT COUNT(*) FROM api_logs` + where
	var total int64
	if err := r.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api logs: %w", err)
	}

	listSQL := `
		SELECT id, method, path, status_code, duration_ms,
		       user_sub, user_email, remote_addr, user_agent, created_at
		FROM api_logs` + where + `
		ORDER BY id DESC
		LIMIT ? OFFSET ?`
	listArgs := append(append([]any{}, args...), limit, offset)

	rows, err := r.db.QueryContext(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list api logs: %w", err)
	}
	defer rows.Close()

	var items []model.APILogEntry
	for rows.Next() {
		var e model.APILogEntry
		if err := rows.Scan(
			&e.ID, &e.Method, &e.Path, &e.StatusCode, &e.DurationMS,
			&e.UserSub, &e.UserEmail, &e.RemoteAddr, &e.UserAgent, &e.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan api log: %w", err)
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if items == nil {
		items = []model.APILogEntry{}
	}
	return items, total, nil
}

func apiLogWhere(f model.APILogFilters) (string, []any) {
	var clauses []string
	var args []any
	if f.Method != "" {
		clauses = append(clauses, "method = ?")
		args = append(args, strings.ToUpper(f.Method))
	}
	if f.Path != "" {
		clauses = append(clauses, "path LIKE ?")
		args = append(args, "%"+f.Path+"%")
	}
	if f.StatusMin > 0 {
		clauses = append(clauses, "status_code >= ?")
		args = append(args, f.StatusMin)
	}
	if f.StatusMax > 0 {
		clauses = append(clauses, "status_code <= ?")
		args = append(args, f.StatusMax)
	}
	if f.User != "" {
		clauses = append(clauses, "(user_email LIKE ? OR user_sub LIKE ?)")
		pat := "%" + f.User + "%"
		args = append(args, pat, pat)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// APILogStats aggregates audit metrics for the Admin UI.
func (r *Repository) APILogStats(ctx context.Context) (model.APILogStats, error) {
	var stats model.APILogStats
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_logs`).Scan(&stats.TotalRequests); err != nil {
		return stats, fmt.Errorf("total requests: %w", err)
	}
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM api_logs
		WHERE date(created_at) = date('now')`).Scan(&stats.RequestsToday); err != nil {
		return stats, fmt.Errorf("requests today: %w", err)
	}
	if err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(AVG(duration_ms), 0) FROM api_logs`).Scan(&stats.AvgDurationMS); err != nil {
		return stats, fmt.Errorf("avg duration: %w", err)
	}
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM api_logs WHERE status_code >= 400`).Scan(&stats.ErrorCount); err != nil {
		return stats, fmt.Errorf("error count: %w", err)
	}
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_sub) FROM api_logs
		WHERE user_sub != ''`).Scan(&stats.UniqueUsers); err != nil {
		return stats, fmt.Errorf("unique users: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT path,
		       COUNT(*) AS cnt,
		       SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors
		FROM api_logs
		GROUP BY path
		ORDER BY cnt DESC
		LIMIT 10`)
	if err != nil {
		return stats, fmt.Errorf("top paths: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var path string
		var cnt, errors int64
		if err := rows.Scan(&path, &cnt, &errors); err != nil {
			return stats, fmt.Errorf("scan top path: %w", err)
		}
		stats.TopPaths = append(stats.TopPaths, [3]any{path, cnt, errors})
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	var last model.CleanupHistoryEntry
	err = r.db.QueryRowContext(ctx, `
		SELECT id, retention_days, deleted_count, triggered_by, cleaned_at
		FROM cleanup_history
		ORDER BY id DESC
		LIMIT 1`).Scan(&last.ID, &last.RetentionDays, &last.DeletedCount, &last.TriggeredBy, &last.CleanedAt)
	if err == nil {
		stats.LastCleanup = &last
	}
	return stats, nil
}

// CleanupAPILogs deletes rows older than retentionDays and records history.
func (r *Repository) CleanupAPILogs(ctx context.Context, retentionDays int, triggeredBy string) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	if triggeredBy == "" {
		triggeredBy = "admin"
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)

	res, err := r.db.ExecContext(ctx, `DELETE FROM api_logs WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete api logs: %w", err)
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO cleanup_history (retention_days, deleted_count, triggered_by, cleaned_at)
		VALUES (?, ?, ?, ?)`,
		retentionDays, deleted, triggeredBy, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return deleted, fmt.Errorf("record cleanup history: %w", err)
	}
	return deleted, nil
}
