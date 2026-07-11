package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/model"
	"github.com/duynhlab/trivy-viewer/internal/storage"
)

// These are characterization tests: they pin the externally observable
// behavior of the search/suggest endpoints so the storage-level
// implementation can change (e.g. move filtering into SQL) without
// changing the HTTP contract the UI depends on (ADR-002).

type testVuln struct {
	ID               string   `json:"vulnerabilityID"`
	Severity         string   `json:"severity"`
	Score            *float64 `json:"score"`
	Resource         string   `json:"resource"`
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion"`
	Title            string   `json:"title"`
}

func vulnData(t *testing.T, vulns ...testVuln) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"report": map[string]any{"vulnerabilities": vulns},
	})
	if err != nil {
		t.Fatalf("marshal vuln data: %v", err)
	}
	return string(b)
}

func sbomData(t *testing.T, comps ...map[string]string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"report": map[string]any{"components": map[string]any{"components": comps}},
	})
	if err != nil {
		t.Fatalf("marshal sbom data: %v", err)
	}
	return string(b)
}

func seedReport(t *testing.T, repo *storage.ReportStore, rep model.Report) {
	t.Helper()
	if err := repo.UpsertReport(context.Background(), rep); err != nil {
		t.Fatalf("seed report %s/%s: %v", rep.Namespace, rep.Name, err)
	}
}

func decodeList[T any](t *testing.T, body []byte) model.ListResponse[T] {
	t.Helper()
	var resp model.ListResponse[T]
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode list: %v; body=%s", err, body)
	}
	return resp
}

func TestSearchVulnerabilitiesMatchFields(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "default", Name: "nginx-abc", ReportType: model.ReportTypeVuln,
		App: "Nginx-App", Image: "registry.io/library/nginx:1.25",
		Data: vulnData(t, testVuln{
			ID: "CVE-2024-0001", Severity: "CRITICAL", Score: new(9.8),
			Resource: "OpenSSL", InstalledVersion: "1.0", FixedVersion: "1.1",
			Title: "Heap Overflow in TLS",
		}),
	})

	cases := []struct {
		name string
		q    string
		want int
	}{
		{"by vulnerability id", "cve-2024-0001", 1},
		{"by title", "heap overflow", 1},
		{"by resource", "openssl", 1},
		{"by app", "nginx-app", 1},
		{"by image", "registry.io/library", 1},
		{"case-insensitive upper query", "OPENSSL", 1},
		{"substring match", "2024-0001", 1},
		{"no match", "log4j", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/search?q="+url.QueryEscape(tc.q))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			resp := decodeList[map[string]any](t, rec.Body.Bytes())
			if len(resp.Items) != tc.want || resp.Total != int64(tc.want) {
				t.Errorf("q=%q: items=%d total=%d, want %d", tc.q, len(resp.Items), resp.Total, tc.want)
			}
		})
	}
}

func TestSearchVulnerabilitiesResultShape(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "edge-a", Namespace: "prod", Name: "api-xyz", ReportType: model.ReportTypeVuln,
		App: "api", Image: "api:2", UpdatedAt: "2026-07-01T00:00:00Z",
		Data: vulnData(t, testVuln{
			ID: "CVE-2025-1111", Severity: "HIGH", Score: new(8.1),
			Resource: "libfoo", InstalledVersion: "2.0", FixedVersion: "2.1", Title: "foo bug",
		}),
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/search?q=CVE-2025-1111")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Items) != 1 {
		t.Fatalf("decode: err=%v items=%d body=%s", err, len(resp.Items), rec.Body.String())
	}
	got := resp.Items[0]
	want := map[string]any{
		"cluster": "edge-a", "namespace": "prod", "name": "api-xyz",
		"app": "api", "image": "api:2",
		"vulnerability_id": "CVE-2025-1111", "severity": "HIGH", "score": 8.1,
		"resource": "libfoo", "installed_version": "2.0", "fixed_version": "2.1",
		"updated_at": "2026-07-01T00:00:00Z",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %q = %v, want %v", k, got[k], v)
		}
	}
}

func TestSearchVulnerabilitiesEmptyQueryReturnsAll(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "r1", ReportType: model.ReportTypeVuln,
		Data: vulnData(t,
			testVuln{ID: "CVE-1", Severity: "LOW"},
			testVuln{ID: "CVE-2", Severity: "HIGH"},
		),
	})
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "b", Name: "r2", ReportType: model.ReportTypeVuln,
		Data: vulnData(t, testVuln{ID: "CVE-3", Severity: "MEDIUM"}),
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/search")
	resp := decodeList[map[string]any](t, rec.Body.Bytes())
	if len(resp.Items) != 3 || resp.Total != 3 {
		t.Errorf("items=%d total=%d, want 3/3", len(resp.Items), resp.Total)
	}
}

func TestSearchVulnerabilitiesPagination(t *testing.T) {
	srv, repo := newTestServer(t)
	vulns := make([]testVuln, 5)
	for i := range vulns {
		vulns[i] = testVuln{ID: fmt.Sprintf("CVE-2024-000%d", i), Severity: "LOW"}
	}
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "default", Name: "r", ReportType: model.ReportTypeVuln,
		Data: vulnData(t, vulns...),
	})

	cases := []struct {
		name      string
		query     string
		wantItems int
		wantFirst string // vulnerability_id of first item, "" = skip check
	}{
		{"first page", "limit=2&offset=0", 2, "CVE-2024-0000"},
		{"second page", "limit=2&offset=2", 2, "CVE-2024-0002"},
		{"last partial page", "limit=2&offset=4", 1, "CVE-2024-0004"},
		{"offset past end", "limit=2&offset=10", 0, ""},
		{"no limit param defaults high", "", 5, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/search?"+tc.query)
			resp := decodeList[map[string]any](t, rec.Body.Bytes())
			if len(resp.Items) != tc.wantItems {
				t.Fatalf("items=%d, want %d; body=%s", len(resp.Items), tc.wantItems, rec.Body.String())
			}
			if resp.Total != 5 {
				t.Errorf("total=%d, want 5 (pre-pagination count)", resp.Total)
			}
			if tc.wantFirst != "" && resp.Items[0]["vulnerability_id"] != tc.wantFirst {
				t.Errorf("first item = %v, want %s", resp.Items[0]["vulnerability_id"], tc.wantFirst)
			}
			if tc.wantItems == 0 && !strings.Contains(rec.Body.String(), `"items":[]`) {
				t.Errorf("empty page must serialize items as [], got %s", rec.Body.String())
			}
		})
	}
}

func TestSearchVulnerabilitiesNewestReportFirst(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "old", ReportType: model.ReportTypeVuln,
		UpdatedAt: "2026-01-01T00:00:00Z",
		Data:      vulnData(t, testVuln{ID: "CVE-OLD", Severity: "LOW"}),
	})
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "new", ReportType: model.ReportTypeVuln,
		UpdatedAt: "2026-06-01T00:00:00Z",
		Data:      vulnData(t, testVuln{ID: "CVE-NEW", Severity: "LOW"}),
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/search")
	resp := decodeList[map[string]any](t, rec.Body.Bytes())
	if len(resp.Items) != 2 {
		t.Fatalf("items=%d, want 2", len(resp.Items))
	}
	if resp.Items[0]["vulnerability_id"] != "CVE-NEW" {
		t.Errorf("first = %v, want CVE-NEW (newest report first)", resp.Items[0]["vulnerability_id"])
	}
}

func TestSearchVulnerabilitiesSkipsMalformedData(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "bad", ReportType: model.ReportTypeVuln,
		Data: `{not json at all`,
	})
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "good", ReportType: model.ReportTypeVuln,
		Data: vulnData(t, testVuln{ID: "CVE-GOOD", Severity: "LOW"}),
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/search")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (malformed rows must be skipped, not fail)", rec.Code)
	}
	resp := decodeList[map[string]any](t, rec.Body.Bytes())
	if len(resp.Items) != 1 || resp.Items[0]["vulnerability_id"] != "CVE-GOOD" {
		t.Errorf("items=%v, want only CVE-GOOD", resp.Items)
	}
}

func TestSearchVulnerabilitiesNullScore(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "r", ReportType: model.ReportTypeVuln,
		Data: vulnData(t, testVuln{ID: "CVE-NOSCORE", Severity: "UNKNOWN", Score: nil}),
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/search?q=CVE-NOSCORE")
	if !strings.Contains(rec.Body.String(), `"score":null`) {
		t.Errorf("missing score must serialize as null, body=%s", rec.Body.String())
	}
}

func TestSuggestVulnerabilities(t *testing.T) {
	srv, repo := newTestServer(t)
	// Duplicate IDs across two reports, one empty ID, unsorted insertion order.
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "r1", ReportType: model.ReportTypeVuln,
		Data: vulnData(t,
			testVuln{ID: "CVE-2024-2222", Severity: "LOW"},
			testVuln{ID: "CVE-2024-1111", Severity: "LOW"},
			testVuln{ID: "", Severity: "LOW"},
		),
	})
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "b", Name: "r2", ReportType: model.ReportTypeVuln,
		Data: vulnData(t,
			testVuln{ID: "CVE-2024-1111", Severity: "LOW"},
			testVuln{ID: "CVE-2023-9999", Severity: "LOW"},
		),
	})

	t.Run("distinct sorted", func(t *testing.T) {
		rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/suggest")
		var got []string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
		}
		want := []string{"CVE-2023-9999", "CVE-2024-1111", "CVE-2024-2222"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("got %v, want %v (deduped + sorted, empty excluded)", got, want)
				break
			}
		}
	})

	t.Run("filter case-insensitive", func(t *testing.T) {
		rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/suggest?q=cve-2023")
		var got []string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 1 || got[0] != "CVE-2023-9999" {
			t.Errorf("got %v, want [CVE-2023-9999]", got)
		}
	})

	t.Run("capped by limit", func(t *testing.T) {
		rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/suggest?limit=2")
		var got []string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("got %d suggestions, want 2 (limit)", len(got))
		}
	})

	t.Run("no match returns empty array", func(t *testing.T) {
		rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports/vulnerabilities/suggest?q=nothing")
		if strings.TrimSpace(rec.Body.String()) != "[]" {
			t.Errorf("want bare [], got %s", rec.Body.String())
		}
	})
}

func TestSearchComponents(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "edge-a", Namespace: "prod", Name: "sb1", ReportType: model.ReportTypeSbom,
		App: "web", Image: "web:1", UpdatedAt: "2026-07-01T00:00:00Z",
		Data: sbomData(t,
			map[string]string{"name": "OpenSSL", "version": "3.0.1", "type": "library"},
			map[string]string{"name": "zlib", "version": "1.3", "type": "library"},
		),
	})
	seedReport(t, repo, model.Report{
		Cluster: "edge-a", Namespace: "prod", Name: "sb-bad", ReportType: model.ReportTypeSbom,
		Data: `broken{`,
	})

	t.Run("match by component name via component param", func(t *testing.T) {
		rec := do(t, srv, http.MethodGet, "/api/v1/sbomreports/components/search?component=openssl")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var resp struct {
			Items []map[string]any `json:"items"`
			Total int64            `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Items) != 1 || resp.Total != 1 {
			t.Fatalf("items=%d total=%d, want 1/1; body=%s", len(resp.Items), resp.Total, rec.Body.String())
		}
		got := resp.Items[0]
		want := map[string]any{
			"cluster": "edge-a", "namespace": "prod", "name": "sb1",
			"app": "web", "image": "web:1",
			"component_name": "OpenSSL", "component_version": "3.0.1", "component_type": "library",
			"updated_at": "2026-07-01T00:00:00Z",
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("field %q = %v, want %v", k, got[k], v)
			}
		}
	})

	t.Run("empty query returns all valid components", func(t *testing.T) {
		rec := do(t, srv, http.MethodGet, "/api/v1/sbomreports/components/search")
		resp := decodeList[map[string]any](t, rec.Body.Bytes())
		if len(resp.Items) != 2 || resp.Total != 2 {
			t.Errorf("items=%d total=%d, want 2/2 (malformed sbom skipped)", len(resp.Items), resp.Total)
		}
	})

	t.Run("pagination", func(t *testing.T) {
		rec := do(t, srv, http.MethodGet, "/api/v1/sbomreports/components/search?limit=1&offset=1")
		resp := decodeList[map[string]any](t, rec.Body.Bytes())
		if len(resp.Items) != 1 || resp.Total != 2 {
			t.Errorf("items=%d total=%d, want 1 item / total 2", len(resp.Items), resp.Total)
		}
	})
}

func TestSuggestComponents(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "sb1", ReportType: model.ReportTypeSbom,
		Data: sbomData(t,
			map[string]string{"name": "zlib", "version": "1.3", "type": "library"},
			map[string]string{"name": "OpenSSL", "version": "3.0", "type": "library"},
			map[string]string{"name": "", "version": "0", "type": "library"},
		),
	})
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "b", Name: "sb2", ReportType: model.ReportTypeSbom,
		Data: sbomData(t, map[string]string{"name": "zlib", "version": "1.2", "type": "library"}),
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/sbomreports/components/suggest")
	var got []string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	want := []string{"OpenSSL", "zlib"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v (deduped, sorted, empty excluded)", got, want)
	}

	rec = do(t, srv, http.MethodGet, "/api/v1/sbomreports/components/suggest?q=ZLI")
	got = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0] != "zlib" {
		t.Errorf("got %v, want [zlib] (case-insensitive)", got)
	}
}
