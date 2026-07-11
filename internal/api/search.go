package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

// vulnSearchResult mirrors the frontend VulnSearchResult type.
type vulnSearchResult struct {
	Cluster          string   `json:"cluster"`
	Namespace        string   `json:"namespace"`
	Name             string   `json:"name"`
	App              string   `json:"app"`
	Image            string   `json:"image"`
	VulnerabilityID  string   `json:"vulnerability_id"`
	Severity         string   `json:"severity"`
	Score            *float64 `json:"score"`
	Resource         string   `json:"resource"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
	UpdatedAt        string   `json:"updated_at"`
}

// componentSearchResult mirrors the frontend ComponentSearchResult type.
type componentSearchResult struct {
	Cluster          string `json:"cluster"`
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	App              string `json:"app"`
	Image            string `json:"image"`
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`
	ComponentType    string `json:"component_type"`
	UpdatedAt        string `json:"updated_at"`
}

const searchScanLimit = 5000

func (s *Server) searchVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := queryInt(r, "limit", defaultSearchLimit)
	offset := queryInt(r, "offset", 0)

	reps, _, err := s.reports.ListReports(r.Context(), model.ReportTypeVuln, model.Filters{Limit: searchScanLimit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var all []vulnSearchResult
	for _, rep := range reps {
		var parsed struct {
			Report struct {
				Vulnerabilities []struct {
					VulnerabilityID  string   `json:"vulnerabilityID"`
					Severity         string   `json:"severity"`
					Score            *float64 `json:"score"`
					Resource         string   `json:"resource"`
					InstalledVersion string   `json:"installedVersion"`
					FixedVersion     string   `json:"fixedVersion"`
					Title            string   `json:"title"`
				} `json:"vulnerabilities"`
			} `json:"report"`
		}
		if json.Unmarshal([]byte(rep.Data), &parsed) != nil {
			continue
		}
		for _, v := range parsed.Report.Vulnerabilities {
			if q != "" && !matchesVuln(q, v.VulnerabilityID, v.Title, v.Resource, rep.App, rep.Image) {
				continue
			}
			all = append(all, vulnSearchResult{
				Cluster: rep.Cluster, Namespace: rep.Namespace, Name: rep.Name,
				App: rep.App, Image: rep.Image,
				VulnerabilityID: v.VulnerabilityID, Severity: v.Severity, Score: v.Score,
				Resource: v.Resource, InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion,
				UpdatedAt: rep.UpdatedAt,
			})
		}
	}

	total := int64(len(all))
	writeJSON(w, http.StatusOK, model.ListResponse[vulnSearchResult]{
		Items: pageVuln(all, offset, limit), Total: total,
	})
}

func (s *Server) suggestVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := queryInt(r, "limit", defaultSuggestLimit)
	reps, _, err := s.reports.ListReports(r.Context(), model.ReportTypeVuln, model.Filters{Limit: searchScanLimit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	seen := map[string]struct{}{}
	for _, rep := range reps {
		var parsed struct {
			Report struct {
				Vulnerabilities []struct {
					VulnerabilityID string `json:"vulnerabilityID"`
				} `json:"vulnerabilities"`
			} `json:"report"`
		}
		if json.Unmarshal([]byte(rep.Data), &parsed) != nil {
			continue
		}
		for _, v := range parsed.Report.Vulnerabilities {
			if v.VulnerabilityID == "" {
				continue
			}
			if q == "" || strings.Contains(strings.ToLower(v.VulnerabilityID), q) {
				seen[v.VulnerabilityID] = struct{}{}
			}
		}
	}
	writeJSON(w, http.StatusOK, sortedSuggestions(seen, limit))
}

func (s *Server) searchComponents(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("component")))
	limit := queryInt(r, "limit", defaultSearchLimit)
	offset := queryInt(r, "offset", 0)

	reps, _, err := s.reports.ListReports(r.Context(), model.ReportTypeSbom, model.Filters{Limit: searchScanLimit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var all []componentSearchResult
	for _, rep := range reps {
		for _, c := range parseComponents(rep.Data) {
			if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
				continue
			}
			all = append(all, componentSearchResult{
				Cluster: rep.Cluster, Namespace: rep.Namespace, Name: rep.Name,
				App: rep.App, Image: rep.Image,
				ComponentName: c.Name, ComponentVersion: c.Version, ComponentType: c.Type,
				UpdatedAt: rep.UpdatedAt,
			})
		}
	}
	total := int64(len(all))
	writeJSON(w, http.StatusOK, model.ListResponse[componentSearchResult]{
		Items: pageComponent(all, offset, limit), Total: total,
	})
}

func (s *Server) suggestComponents(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := queryInt(r, "limit", defaultSuggestLimit)
	reps, _, err := s.reports.ListReports(r.Context(), model.ReportTypeSbom, model.Filters{Limit: searchScanLimit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	seen := map[string]struct{}{}
	for _, rep := range reps {
		for _, c := range parseComponents(rep.Data) {
			if c.Name == "" {
				continue
			}
			if q == "" || strings.Contains(strings.ToLower(c.Name), q) {
				seen[c.Name] = struct{}{}
			}
		}
	}
	writeJSON(w, http.StatusOK, sortedSuggestions(seen, limit))
}

type sbomComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// parseComponents extracts CycloneDX components from an SBOM report's data JSON.
func parseComponents(data string) []sbomComponent {
	var parsed struct {
		Report struct {
			Components struct {
				Components []sbomComponent `json:"components"`
			} `json:"components"`
		} `json:"report"`
	}
	if json.Unmarshal([]byte(data), &parsed) != nil {
		return nil
	}
	return parsed.Report.Components.Components
}

func matchesVuln(q string, fields ...string) bool {
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func sortedSuggestions(set map[string]struct{}, limit int) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func pageVuln(items []vulnSearchResult, offset, limit int) []vulnSearchResult {
	lo, hi := pageBounds(len(items), offset, limit)
	out := items[lo:hi]
	if out == nil {
		out = []vulnSearchResult{}
	}
	return out
}

func pageComponent(items []componentSearchResult, offset, limit int) []componentSearchResult {
	lo, hi := pageBounds(len(items), offset, limit)
	out := items[lo:hi]
	if out == nil {
		out = []componentSearchResult{}
	}
	return out
}

func pageBounds(n, offset, limit int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > n {
		offset = n
	}
	hi := n
	if limit > 0 && offset+limit < n {
		hi = offset + limit
	}
	return offset, hi
}
