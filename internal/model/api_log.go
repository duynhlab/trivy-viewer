package model

// APILogEntry is a row from api_logs for the Admin audit UI.
type APILogEntry struct {
	ID         int64  `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	DurationMS int    `json:"duration_ms"`
	UserSub    string `json:"user_sub"`
	UserEmail  string `json:"user_email"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent"`
	CreatedAt  string `json:"created_at"`
}

// APILogFilters are query parameters for listing audit logs.
type APILogFilters struct {
	Method    string
	Path      string
	StatusMin int
	StatusMax int
	User      string
	Limit     int
	Offset    int
}

// CleanupHistoryEntry records an api_logs purge.
type CleanupHistoryEntry struct {
	ID            int64  `json:"id"`
	RetentionDays int    `json:"retention_days"`
	DeletedCount  int64  `json:"deleted_count"`
	TriggeredBy   string `json:"triggered_by"`
	CleanedAt     string `json:"cleaned_at"`
}

// APILogStats powers the Admin audit dashboard cards.
type APILogStats struct {
	TotalRequests int64                `json:"total_requests"`
	RequestsToday int64                `json:"requests_today"`
	AvgDurationMS float64              `json:"avg_duration_ms"`
	ErrorCount    int64                `json:"error_count"`
	UniqueUsers   int64                `json:"unique_users"`
	TopPaths      [][3]any             `json:"top_paths"`
	LastCleanup   *CleanupHistoryEntry `json:"last_cleanup"`
}
