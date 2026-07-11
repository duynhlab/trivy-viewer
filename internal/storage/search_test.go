package storage

import (
	"context"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

func seedSearchReport(t *testing.T, repo *ReportStore, name, reportType, data string) {
	t.Helper()
	err := repo.UpsertReport(context.Background(), model.Report{
		Cluster: "hub", Namespace: "default", Name: name, ReportType: reportType,
		App: name, Image: name + ":1", Data: data,
	})
	if err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

func TestSearchVulnerabilitiesSQLEdgeCases(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	seedSearchReport(t, repo, "malformed", model.ReportTypeVuln, `{oops`)
	seedSearchReport(t, repo, "no-report-path", model.ReportTypeVuln, `{"kind":"VulnerabilityReport"}`)
	seedSearchReport(t, repo, "null-score", model.ReportTypeVuln,
		`{"report":{"vulnerabilities":[{"vulnerabilityID":"CVE-A","severity":"LOW","score":null}]}}`)
	seedSearchReport(t, repo, "scored", model.ReportTypeVuln,
		`{"report":{"vulnerabilities":[{"vulnerabilityID":"CVE-B","severity":"HIGH","score":7.5}]}}`)

	items, total, err := repo.SearchVulnerabilities(ctx, "", 0, 0)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("total=%d len=%d, want 2/2 (malformed + missing path skipped)", total, len(items))
	}
	byID := map[string]model.VulnSearchResult{}
	for _, it := range items {
		byID[it.VulnerabilityID] = it
	}
	if byID["CVE-A"].Score != nil {
		t.Errorf("CVE-A score = %v, want nil (JSON null)", *byID["CVE-A"].Score)
	}
	if s := byID["CVE-B"].Score; s == nil || *s != 7.5 {
		t.Errorf("CVE-B score = %v, want 7.5", s)
	}

	// Offset past the result set: empty non-nil slice, total unchanged.
	items, total, err = repo.SearchVulnerabilities(ctx, "", 10, 99)
	if err != nil {
		t.Fatalf("search offset past end: %v", err)
	}
	if total != 2 || items == nil || len(items) != 0 {
		t.Errorf("offset past end: total=%d items=%#v, want total 2 and empty slice", total, items)
	}

	// Negative limit means no limit.
	items, _, err = repo.SearchVulnerabilities(ctx, "", -5, 0)
	if err != nil || len(items) != 2 {
		t.Errorf("negative limit: err=%v len=%d, want 2", err, len(items))
	}
}

func TestSuggestSQLEdgeCases(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	seedSearchReport(t, repo, "r1", model.ReportTypeVuln,
		`{"report":{"vulnerabilities":[
			{"vulnerabilityID":"CVE-2"},{"vulnerabilityID":"CVE-1"},{"vulnerabilityID":""},{"vulnerabilityID":"CVE-2"}
		]}}`)

	got, err := repo.SuggestVulnerabilityIDs(ctx, "", 10)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if len(got) != 2 || got[0] != "CVE-1" || got[1] != "CVE-2" {
		t.Errorf("got %v, want [CVE-1 CVE-2] (distinct, sorted, empty excluded)", got)
	}

	got, err = repo.SuggestVulnerabilityIDs(ctx, "no-match", 10)
	if err != nil {
		t.Fatalf("suggest no match: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("no match must return empty non-nil slice, got %#v", got)
	}
}

func TestSearchComponentsSQLEdgeCases(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	seedSearchReport(t, repo, "sbom1", model.ReportTypeSbom,
		`{"report":{"components":{"components":[
			{"name":"libssl","version":"3.0","type":"library"},
			{"version":"1.0","type":"library"}
		]}}}`)
	seedSearchReport(t, repo, "sbom-malformed", model.ReportTypeSbom, `]`)
	// A vuln report must never leak into component search.
	seedSearchReport(t, repo, "vuln", model.ReportTypeVuln,
		`{"report":{"vulnerabilities":[{"vulnerabilityID":"CVE-X"}]}}`)

	items, total, err := repo.SearchComponents(ctx, "", 0, 0)
	if err != nil {
		t.Fatalf("search components: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("total=%d len=%d, want 2 (nameless component still a row; malformed skipped)", total, len(items))
	}
	if items[0].ComponentName != "libssl" || items[1].ComponentName != "" {
		t.Errorf("components = %q,%q, want libssl and empty name", items[0].ComponentName, items[1].ComponentName)
	}

	// Name filter must exclude the nameless component.
	items, total, err = repo.SearchComponents(ctx, "libssl", 0, 0)
	if err != nil || total != 1 || len(items) != 1 {
		t.Errorf("filter libssl: err=%v total=%d len=%d, want 1", err, total, len(items))
	}
}
