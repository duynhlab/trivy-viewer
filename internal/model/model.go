// Package model holds the domain types shared across storage, watcher, and API.
// JSON tags match the shapes the reused upstream React UI expects
// (see frontend/src/types.ts); see ADR-002 for the compatibility contract.
package model

// Report type discriminators, matching the lowercased Kubernetes kind.
const (
	ReportTypeVuln = "vulnerabilityreport"
	ReportTypeSbom = "sbomreport"
)

// Report is a single stored report row (the denormalized read-model). The
// natural key is (Cluster, Namespace, Name, ReportType). Data holds the full
// report JSON for detail views and search.
type Report struct {
	ID              int64
	Cluster         string
	Namespace       string
	Name            string
	ReportType      string
	App             string
	Image           string
	Registry        string
	Critical        int
	High            int
	Medium          int
	Low             int
	Unknown         int
	ComponentsCount int
	Data            string // full report JSON
	ReceivedAt      string // RFC3339
	UpdatedAt       string // RFC3339
	Notes           string
	NotesCreatedAt  *string
	NotesUpdatedAt  *string
}

// VulnSummary is the per-report severity breakdown.
type VulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// ReportMeta is the list/detail metadata shape the UI consumes.
type ReportMeta struct {
	Cluster         string      `json:"cluster"`
	Namespace       string      `json:"namespace"`
	Name            string      `json:"name"`
	App             string      `json:"app"`
	Image           string      `json:"image"`
	Registry        string      `json:"registry"`
	Summary         VulnSummary `json:"summary"`
	ComponentsCount int         `json:"components_count"`
	Notes           string      `json:"notes"`
	NotesCreatedAt  *string     `json:"notes_created_at"`
	NotesUpdatedAt  *string     `json:"notes_updated_at"`
	UpdatedAt       string      `json:"updated_at"`
}

// Meta projects a Report row into the UI metadata shape.
func (r Report) Meta() ReportMeta {
	return ReportMeta{
		Cluster:         r.Cluster,
		Namespace:       r.Namespace,
		Name:            r.Name,
		App:             r.App,
		Image:           r.Image,
		Registry:        r.Registry,
		Summary:         VulnSummary{r.Critical, r.High, r.Medium, r.Low, r.Unknown},
		ComponentsCount: r.ComponentsCount,
		Notes:           r.Notes,
		NotesCreatedAt:  r.NotesCreatedAt,
		NotesUpdatedAt:  r.NotesUpdatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

// ClusterInfo is one row of the clusters view.
type ClusterInfo struct {
	Name            string `json:"name"`
	VulnReportCount int64  `json:"vuln_report_count"`
	SbomReportCount int64  `json:"sbom_report_count"`
}

// Stats is the dashboard aggregate.
type Stats struct {
	TotalClusters    int64  `json:"total_clusters"`
	TotalVulnReports int64  `json:"total_vuln_reports"`
	TotalSbomReports int64  `json:"total_sbom_reports"`
	TotalCritical    int64  `json:"total_critical"`
	TotalHigh        int64  `json:"total_high"`
	TotalMedium      int64  `json:"total_medium"`
	TotalLow         int64  `json:"total_low"`
	TotalUnknown     int64  `json:"total_unknown"`
	SqliteVersion    string `json:"sqlite_version"`
	DBSizeBytes      int64  `json:"db_size_bytes"`
	DBSizeHuman      string `json:"db_size_human"`
}

// ListResponse is the generic list envelope the UI expects.
type ListResponse[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
}

// Filters are the query parameters for listing reports.
type Filters struct {
	Cluster   string
	Namespace string
	App       string
	Component string
	Limit     int
	Offset    int
}
