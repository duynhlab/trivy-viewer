package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/duynhlab/trivy-viewer/internal/model"
	"github.com/duynhlab/trivy-viewer/internal/storage"
	"github.com/go-chi/chi/v5"
)

// fullReport is the {meta, data} shape the UI detail views consume. data is the
// raw report JSON re-emitted as an object.
type fullReport struct {
	Meta model.ReportMeta `json:"meta"`
	Data json.RawMessage  `json:"data"`
}

func (s *Server) filtersFrom(r *http.Request) model.Filters {
	q := r.URL.Query()
	return model.Filters{
		Cluster:   q.Get("cluster"),
		Namespace: q.Get("namespace"),
		App:       q.Get("app"),
		Component: q.Get("component"),
		Limit:     queryInt(r, "limit", 0),
		Offset:    queryInt(r, "offset", 0),
	}
}

func (s *Server) listReports(w http.ResponseWriter, r *http.Request, reportType string) {
	reps, total, err := s.repo.ListReports(r.Context(), reportType, s.filtersFrom(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items := make([]model.ReportMeta, 0, len(reps))
	for _, rep := range reps {
		items = append(items, rep.Meta())
	}
	writeJSON(w, http.StatusOK, model.ListResponse[model.ReportMeta]{Items: items, Total: total})
}

func (s *Server) listVulnReports(w http.ResponseWriter, r *http.Request) {
	s.listReports(w, r, model.ReportTypeVuln)
}

func (s *Server) listSbomReports(w http.ResponseWriter, r *http.Request) {
	s.listReports(w, r, model.ReportTypeSbom)
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request, reportType string) {
	rep, err := s.repo.GetReport(r.Context(),
		chi.URLParam(r, "cluster"), chi.URLParam(r, "namespace"), chi.URLParam(r, "name"), reportType)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "report not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data := json.RawMessage(rep.Data)
	if !json.Valid(data) {
		data = json.RawMessage("null")
	}
	writeJSON(w, http.StatusOK, fullReport{Meta: rep.Meta(), Data: data})
}

func (s *Server) getVulnReport(w http.ResponseWriter, r *http.Request) {
	s.getReport(w, r, model.ReportTypeVuln)
}

func (s *Server) getSbomReport(w http.ResponseWriter, r *http.Request) {
	s.getReport(w, r, model.ReportTypeSbom)
}

func (s *Server) updateNotes(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	err := s.repo.UpdateNotes(r.Context(),
		chi.URLParam(r, "cluster"), chi.URLParam(r, "reportType"),
		chi.URLParam(r, "namespace"), chi.URLParam(r, "name"), body.Notes)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "report not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
