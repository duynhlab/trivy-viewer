package storage

import (
	"context"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

func TestAPILogsListFilterAndStats(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	entries := []struct {
		method string
		path   string
		status int
		ms     int
		user   string
	}{
		{"GET", "/api/v1/stats", 200, 10, ""},
		{"GET", "/api/v1/clusters", 200, 20, ""},
		{"POST", "/api/v1/hub/clusters", 201, 50, ""},
		{"GET", "/api/v1/vulnerabilityreports", 500, 5, ""},
	}
	for _, e := range entries {
		if err := repo.InsertAPILog(ctx, modelAPILog(e.method, e.path, e.status, e.ms)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	items, total, err := repo.ListAPILogs(ctx, model.APILogFilters{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 4 || len(items) != 4 {
		t.Fatalf("total=%d len=%d, want 4", total, len(items))
	}

	items, total, err = repo.ListAPILogs(ctx, model.APILogFilters{Method: "GET", StatusMin: 400, Limit: 10})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Path != "/api/v1/vulnerabilityreports" {
		t.Fatalf("filtered: total=%d item=%+v", total, items)
	}

	stats, err := repo.APILogStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.TotalRequests != 4 || stats.ErrorCount != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	if len(stats.TopPaths) == 0 {
		t.Fatal("expected top paths")
	}

	deleted, err := repo.CleanupAPILogs(ctx, 0, "test")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("deleted=%d want 0 for retention 0->7 same day", deleted)
	}
}

func modelAPILog(method, path string, status, ms int) model.APILogEntry {
	return model.APILogEntry{
		Method: method, Path: path, StatusCode: status, DurationMS: ms,
		CreatedAt: "2026-07-09T12:00:00Z",
	}
}
