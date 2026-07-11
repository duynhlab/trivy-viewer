package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

func (s *Server) listAPILogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.APILogFilters{
		Method:    q.Get("method"),
		Path:      q.Get("path"),
		StatusMin: queryInt(r, "status_min", 0),
		StatusMax: queryInt(r, "status_max", 0),
		User:      q.Get("user"),
		Limit:     queryInt(r, "limit", 50),
		Offset:    queryInt(r, "offset", 0),
	}
	items, total, err := s.repo.ListAPILogs(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, model.ListResponse[model.APILogEntry]{Items: items, Total: total})
}

func (s *Server) apiLogStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.repo.APILogStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if stats.TopPaths == nil {
		stats.TopPaths = [][3]any{}
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) cleanupAPILogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	days := queryInt(r, "retention_days", 7)
	deleted, err := s.repo.CleanupAPILogs(r.Context(), days, "admin")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted":        deleted,
		"retention_days": days,
	})
}

func shouldAuditLog(path string) bool {
	return strings.HasPrefix(path, "/api/v1/")
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
