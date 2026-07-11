package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/duynhlab/trivy-viewer/internal/model"
	"github.com/duynhlab/trivy-viewer/internal/storage"
	"github.com/duynhlab/trivy-viewer/internal/web"
)

func newTestServer(t *testing.T) (*Server, *storage.ReportStore) {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := storage.NewReportStore(db)
	cfg := &config.Config{Mode: config.ModeServer, LogFormat: "json", LogLevel: "info", ServerPort: 3000, StoragePath: t.TempDir(), AuthMode: "none"}
	srv := New(Options{Reports: repo, Audit: storage.NewAPILogStore(db), Config: cfg, DBPath: db.Path()})
	return srv, repo
}

func do(t *testing.T, srv *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestListVulnReportsShape(t *testing.T) {
	srv, repo := newTestServer(t)
	_ = repo.UpsertReport(context.Background(), model.Report{
		Cluster: "hub", Namespace: "default", Name: "a", ReportType: model.ReportTypeVuln,
		Critical: 2, Data: `{"kind":"VulnerabilityReport"}`,
	})

	rec := do(t, srv, http.MethodGet, "/api/v1/vulnerabilityreports")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp model.ListResponse[model.ReportMeta]
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("total=%d items=%d, want 1/1", resp.Total, len(resp.Items))
	}
	if resp.Items[0].Summary.Critical != 2 {
		t.Errorf("critical = %d, want 2", resp.Items[0].Summary.Critical)
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv, repo := newTestServer(t)
	_ = repo.UpsertReport(context.Background(), model.Report{
		Cluster: "hub", Namespace: "default", Name: "a", ReportType: model.ReportTypeVuln,
		Critical: 3, High: 1, Data: `{}`,
	})
	rec := do(t, srv, http.MethodGet, "/api/v1/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var s model.Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.TotalCritical != 3 || s.TotalClusters != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestAuthStubs(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, http.MethodGet, "/api/v1/auth/tokens")
	if rec.Code != http.StatusOK {
		t.Fatalf("tokens status = %d, want 200", rec.Code)
	}
	rec = do(t, srv, http.MethodGet, "/api/v1/auth/me")
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d, want 200", rec.Code)
	}
}

func TestAlertsNotImplemented(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, http.MethodGet, "/api/v1/alerts")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("alerts status = %d, want 501", rec.Code)
	}
}

func TestClusterRegistrationRequiresKube(t *testing.T) {
	srv, _ := newTestServer(t) // no kube client configured
	rec := do(t, srv, http.MethodGet, "/api/v1/hub/clusters")
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412 when no kube access", rec.Code)
	}
}

func TestSPAFallbackServesIndex(t *testing.T) {
	srv, _ := newTestServer(t)
	ui, err := web.Handler()
	if err != nil {
		t.Fatalf("web handler: %v", err)
	}
	srv.uiHandler = ui
	rec := do(t, srv, http.MethodGet, "/some/client/route")
	if rec.Code != http.StatusOK {
		t.Fatalf("SPA fallback status = %d, want 200", rec.Code)
	}
}
