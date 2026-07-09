package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

func TestAdminLogsEndpoints(t *testing.T) {
	srv, repo := newTestServer(t)
	ctx := context.Background()

	_ = repo.InsertAPILog(ctx, model.APILogEntry{
		Method: "GET", Path: "/api/v1/stats", StatusCode: 200, DurationMS: 12,
		CreatedAt: "2026-07-09T12:00:00Z",
	})
	_ = repo.InsertAPILog(ctx, model.APILogEntry{
		Method: "GET", Path: "/api/v1/clusters", StatusCode: 404, DurationMS: 3,
		CreatedAt: "2026-07-09T12:01:00Z",
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/admin/logs?limit=10")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}
	var list model.ListResponse[model.APILogEntry]
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Total < 2 || len(list.Items) < 2 {
		t.Fatalf("list: total=%d len=%d", list.Total, len(list.Items))
	}

	rec = do(t, srv, http.MethodGet, "/api/v1/admin/logs/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("stats status=%d", rec.Code)
	}
	var stats model.APILogStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if stats.TotalRequests < 2 || stats.ErrorCount != 1 {
		t.Fatalf("stats: %+v", stats)
	}

	// Middleware records this request too.
	rec = do(t, srv, http.MethodGet, "/api/v1/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("version status=%d", rec.Code)
	}
	rec = do(t, srv, http.MethodGet, "/api/v1/admin/logs/stats")
	var statsAfter model.APILogStats
	_ = json.Unmarshal(rec.Body.Bytes(), &statsAfter)
	if statsAfter.TotalRequests < 3 {
		t.Fatalf("expected middleware audit rows, got %+v", statsAfter)
	}
}

func TestAdminLogsNot501(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, http.MethodGet, "/api/v1/admin/logs")
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("admin logs still returns 501")
	}
}
