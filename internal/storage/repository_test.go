package storage

import (
	"context"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

func newTestRepo(t *testing.T) *Repository {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewRepository(db)
}

func sampleVuln(cluster, ns, name string, crit, high int) model.Report {
	return model.Report{
		Cluster: cluster, Namespace: ns, Name: name, ReportType: model.ReportTypeVuln,
		App: name, Image: name + ":latest", Registry: "docker.io",
		Critical: crit, High: high, Data: `{"kind":"VulnerabilityReport"}`,
	}
}

func TestUpsertIsIdempotentOnNaturalKey(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	rep := sampleVuln("hub", "default", "app-1", 1, 2)
	if err := repo.UpsertReport(ctx, rep); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	rep.Critical = 5
	if err := repo.UpsertReport(ctx, rep); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	items, total, err := repo.ListReports(ctx, model.ReportTypeVuln, model.Filters{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1 (upsert must not duplicate)", total)
	}
	if items[0].Critical != 5 {
		t.Errorf("critical = %d, want 5 (update should apply)", items[0].Critical)
	}
}

func TestListFilters(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_ = repo.UpsertReport(ctx, sampleVuln("hub", "default", "a", 1, 0))
	_ = repo.UpsertReport(ctx, sampleVuln("hub", "prod", "b", 0, 1))
	_ = repo.UpsertReport(ctx, sampleVuln("edge", "prod", "c", 0, 0))

	items, total, err := repo.ListReports(ctx, model.ReportTypeVuln, model.Filters{Cluster: "hub"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Errorf("cluster=hub total=%d len=%d, want 2/2", total, len(items))
	}

	items, total, err = repo.ListReports(ctx, model.ReportTypeVuln, model.Filters{Namespace: "prod"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Errorf("namespace=prod total=%d len=%d, want 2/2", total, len(items))
	}
}

func TestGetReportNotFound(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	_, err := repo.GetReport(ctx, "nope", "nope", "nope", model.ReportTypeVuln)
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteByClusterPurges(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	_ = repo.UpsertReport(ctx, sampleVuln("hub", "default", "a", 1, 0))
	_ = repo.UpsertReport(ctx, sampleVuln("edge", "default", "b", 0, 1))

	n, err := repo.DeleteByCluster(ctx, "edge")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1", n)
	}
	clusters, err := repo.ListClusters(ctx)
	if err != nil {
		t.Fatalf("list clusters: %v", err)
	}
	if len(clusters) != 1 || clusters[0].Name != "hub" {
		t.Errorf("clusters = %+v, want only hub", clusters)
	}
}

func TestStatsAggregates(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	_ = repo.UpsertReport(ctx, sampleVuln("hub", "default", "a", 2, 3))
	_ = repo.UpsertReport(ctx, sampleVuln("edge", "default", "b", 1, 1))
	sbom := model.Report{
		Cluster: "hub", Namespace: "default", Name: "a", ReportType: model.ReportTypeSbom,
		ComponentsCount: 10, Data: `{"kind":"SbomReport"}`,
	}
	_ = repo.UpsertReport(ctx, sbom)

	s, err := repo.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if s.TotalClusters != 2 {
		t.Errorf("TotalClusters = %d, want 2", s.TotalClusters)
	}
	if s.TotalVulnReports != 2 {
		t.Errorf("TotalVulnReports = %d, want 2", s.TotalVulnReports)
	}
	if s.TotalSbomReports != 1 {
		t.Errorf("TotalSbomReports = %d, want 1", s.TotalSbomReports)
	}
	if s.TotalCritical != 3 {
		t.Errorf("TotalCritical = %d, want 3", s.TotalCritical)
	}
	if s.TotalHigh != 4 {
		t.Errorf("TotalHigh = %d, want 4", s.TotalHigh)
	}
}

func TestUpdateNotesPreservedOnUpsert(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	rep := sampleVuln("hub", "default", "a", 1, 0)
	_ = repo.UpsertReport(ctx, rep)

	if err := repo.UpdateNotes(ctx, "hub", model.ReportTypeVuln, "default", "a", "triaged"); err != nil {
		t.Fatalf("update notes: %v", err)
	}
	// Re-upsert (as the watcher would on a report change) must not wipe notes.
	rep.Critical = 9
	_ = repo.UpsertReport(ctx, rep)

	got, err := repo.GetReport(ctx, "hub", "default", "a", model.ReportTypeVuln)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Notes != "triaged" {
		t.Errorf("notes = %q, want \"triaged\" (must survive upsert)", got.Notes)
	}
	if got.Critical != 9 {
		t.Errorf("critical = %d, want 9", got.Critical)
	}
}
