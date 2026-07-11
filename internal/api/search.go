package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

// Search endpoints delegate filtering and pagination to the report store
// (SQLite JSON1); handlers only parse parameters and shape the response.

func (s *Server) searchVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := queryInt(r, "limit", defaultSearchLimit)
	offset := queryInt(r, "offset", 0)

	items, total, err := s.reports.SearchVulnerabilities(r.Context(), q, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, model.ListResponse[model.VulnSearchResult]{Items: items, Total: total})
}

func (s *Server) suggestVulnerabilities(w http.ResponseWriter, r *http.Request) {
	s.suggest(w, r, s.reports.SuggestVulnerabilityIDs)
}

func (s *Server) searchComponents(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("component")))
	limit := queryInt(r, "limit", defaultSearchLimit)
	offset := queryInt(r, "offset", 0)

	items, total, err := s.reports.SearchComponents(r.Context(), q, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, model.ListResponse[model.ComponentSearchResult]{Items: items, Total: total})
}

func (s *Server) suggestComponents(w http.ResponseWriter, r *http.Request) {
	s.suggest(w, r, s.reports.SuggestComponents)
}

// suggest shares the parameter parsing and response shape (a bare JSON array)
// of the two suggest endpoints.
func (s *Server) suggest(w http.ResponseWriter, r *http.Request, fetch func(ctx context.Context, q string, limit int) ([]string, error)) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := queryInt(r, "limit", defaultSuggestLimit)

	out, err := fetch(r.Context(), q, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
