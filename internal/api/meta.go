package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/buildinfo"
	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/duynhlab/trivy-viewer/internal/model"
)

func (s *Server) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.repo.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats.SqliteVersion = "modernc-sqlite"
	if fi, err := os.Stat(s.dbPath); err == nil {
		stats.DBSizeBytes = fi.Size()
	}
	stats.DBSizeHuman = humanBytes(stats.DBSizeBytes)
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) listClusters(w http.ResponseWriter, r *http.Request) {
	clusters, err := s.repo.ListClusters(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if clusters == nil {
		clusters = []model.ClusterInfo{}
	}
	writeJSON(w, http.StatusOK, model.ListResponse[model.ClusterInfo]{Items: clusters, Total: int64(len(clusters))})
}

func (s *Server) listNamespaces(w http.ResponseWriter, r *http.Request) {
	nss, err := s.repo.ListNamespaces(r.Context(), r.URL.Query().Get("cluster"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if nss == nil {
		nss = []string{}
	}
	writeJSON(w, http.StatusOK, model.ListResponse[string]{Items: nss, Total: int64(len(nss))})
}

// getTrends returns a minimal trend payload. Historical trends are a v2 item;
// for v1 we return the current snapshot as a single data point so the dashboard
// renders without error.
func (s *Server) getTrends(w http.ResponseWriter, r *http.Request) {
	stats, err := s.repo.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Cluster names only decorate the trends meta block; degrade to an empty
	// list rather than failing the whole dashboard if the view query errors.
	clusters, err := s.repo.ListClusters(r.Context())
	if err != nil {
		slog.Warn("trends: list clusters failed", "error", err)
	}
	names := make([]string, 0, len(clusters))
	for _, c := range clusters {
		names = append(names, c.Name)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, map[string]any{
		"meta": map[string]any{
			"range_start": now, "range_end": now, "granularity": "day",
			"clusters": names, "data_from": nil, "data_to": nil,
		},
		"series": []map[string]any{{
			"date":           now,
			"vuln_reports":   stats.TotalVulnReports,
			"sbom_reports":   stats.TotalSbomReports,
			"critical":       stats.TotalCritical,
			"high":           stats.TotalHigh,
			"medium":         stats.TotalMedium,
			"low":            stats.TotalLow,
			"unknown":        stats.TotalUnknown,
			"clusters_count": stats.TotalClusters,
		}},
	})
}

func (s *Server) watcherStatus(w http.ResponseWriter, r *http.Request) {
	vuln, err := s.repo.CountByType(r.Context(), model.ReportTypeVuln)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sbom, err := s.repo.CountByType(r.Context(), model.ReportTypeSbom)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	info := func(n int64) map[string]any {
		return map[string]any{"running": true, "initial_sync_done": true, "reports_count": n}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vuln_watcher": info(vuln),
		"sbom_watcher": info(sbom),
	})
}

func (s *Server) getVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":      buildinfo.Version,
		"commit":       buildinfo.Commit,
		"build_date":   buildinfo.BuildDate,
		"rust_version": "",
		"rust_channel": "go",
		"llvm_version": "",
		"platform":     runtime.GOOS + "/" + runtime.GOARCH,
	})
}

func (s *Server) getStatus(w http.ResponseWriter, _ *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, map[string]any{
		"hostname":   host,
		"uptime":     time.Since(s.startedAt).Truncate(time.Second).String(),
		"collectors": 0,
	})
}

// getConfig echoes non-secret effective configuration.
func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	item := func(env, val string, sensitive bool) map[string]any {
		return map[string]any{"env": env, "value": val, "sensitive": sensitive}
	}
	items := []map[string]any{
		item(config.EnvMode, string(s.cfg.Mode), false),
		item(config.EnvLogFormat, s.cfg.LogFormat, false),
		item(config.EnvLogLevel, s.cfg.LogLevel, false),
		item(config.EnvServerPort, fmt.Sprintf("%d", s.cfg.ServerPort), false),
		item(config.EnvStoragePath, s.cfg.StoragePath, false),
		item(config.EnvAuthMode, s.cfg.AuthMode, false),
		item(config.EnvHubSecretNamespace, s.hubNamespace, false),
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
