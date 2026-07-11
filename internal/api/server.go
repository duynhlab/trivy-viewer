// Package api implements the server-mode HTTP surface: the REST API consumed by
// the reused upstream React UI plus the embedded static assets. The contract is
// fixed by the embedded frontend (API contract).
package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/duynhlab/trivy-viewer/internal/metrics"
	"github.com/duynhlab/trivy-viewer/internal/model"
	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// ReportStore is the report surface the handlers consume. The interface is
// defined here, on the consumer side, and satisfied implicitly by
// *storage.ReportStore ("accept interfaces, return structs").
type ReportStore interface {
	ListReports(ctx context.Context, reportType string, f model.Filters) ([]model.Report, int64, error)
	GetReport(ctx context.Context, cluster, namespace, name, reportType string) (model.Report, error)
	UpdateNotes(ctx context.Context, cluster, reportType, namespace, name, notes string) error
	ListClusters(ctx context.Context) ([]model.ClusterInfo, error)
	ListNamespaces(ctx context.Context, cluster string) ([]string, error)
	Stats(ctx context.Context) (model.Stats, error)
	CountByType(ctx context.Context, reportType string) (int64, error)
}

// AuditLogStore is the audit-log surface consumed by the admin handlers and
// the request-logging middleware. Satisfied by *storage.APILogStore.
type AuditLogStore interface {
	InsertAPILog(ctx context.Context, entry model.APILogEntry) error
	ListAPILogs(ctx context.Context, f model.APILogFilters) ([]model.APILogEntry, int64, error)
	APILogStats(ctx context.Context) (model.APILogStats, error)
	CleanupAPILogs(ctx context.Context, retentionDays int, triggeredBy string) (int64, error)
}

// Server holds the dependencies for the HTTP handlers.
type Server struct {
	reports ReportStore
	audit   AuditLogStore
	cfg     *config.Config
	metrics *metrics.Metrics
	dbPath  string

	// kube and hubNamespace back the cluster-registration endpoints. kube may be
	// nil when no cluster is reachable (local dev); those endpoints then fail
	// with a clear message rather than panicking.
	kube         kubernetes.Interface
	hubNamespace string

	// uiHandler serves the embedded frontend with SPA fallback.
	uiHandler http.Handler

	startedAt time.Time
}

// Options configures a Server.
type Options struct {
	Reports      ReportStore
	Audit        AuditLogStore
	Config       *config.Config
	Metrics      *metrics.Metrics
	DBPath       string
	Kube         kubernetes.Interface
	HubNamespace string
	UIHandler    http.Handler
}

// New builds a Server.
func New(o Options) *Server {
	return &Server{
		reports:      o.Reports,
		audit:        o.Audit,
		cfg:          o.Config,
		metrics:      o.Metrics,
		dbPath:       o.DBPath,
		kube:         o.Kube,
		hubNamespace: o.HubNamespace,
		uiHandler:    o.UIHandler,
		startedAt:    time.Now(),
	}
}

// Router builds the HTTP handler with API routes and the SPA fallback.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.metricsMiddleware)

	r.Route("/api/v1", func(r chi.Router) {
		// Reports.
		r.Get("/vulnerabilityreports", s.listVulnReports)
		r.Get("/vulnerabilityreports/vulnerabilities/search", s.searchVulnerabilities)
		r.Get("/vulnerabilityreports/vulnerabilities/suggest", s.suggestVulnerabilities)
		r.Get("/vulnerabilityreports/{cluster}/{namespace}/{name}", s.getVulnReport)
		r.Get("/sbomreports", s.listSbomReports)
		r.Get("/sbomreports/components/search", s.searchComponents)
		r.Get("/sbomreports/components/suggest", s.suggestComponents)
		r.Get("/sbomreports/{cluster}/{namespace}/{name}", s.getSbomReport)
		r.Put("/reports/{cluster}/{reportType}/{namespace}/{name}/notes", s.updateNotes)

		// Dashboard / meta.
		r.Get("/stats", s.getStats)
		r.Get("/clusters", s.listClusters)
		r.Get("/namespaces", s.listNamespaces)
		r.Get("/dashboard/trends", s.getTrends)
		r.Get("/watcher/status", s.watcherStatus)
		r.Get("/version", s.getVersion)
		r.Get("/status", s.getStatus)
		r.Get("/config", s.getConfig)

		// Hub cluster registration.
		r.Get("/hub/clusters", s.listRegisteredClusters)
		r.Post("/hub/clusters", s.registerCluster)
		r.Post("/hub/clusters/validate", s.validateCluster)
		r.Delete("/hub/clusters/{name}", s.deleteRegisteredCluster)
		r.Get("/hub/manifests", s.registrationManifests)

		// Auth stubs (auth: none).
		r.Get("/auth/me", s.authMe)
		r.Get("/auth/tokens", s.authTokens)

		// Deferred to v2.
		r.Handle("/alerts", notImplemented("alerts"))
		r.Handle("/alerts/*", notImplemented("alerts"))

		// API audit log (upstream-compatible).
		r.Get("/admin/logs", s.listAPILogs)
		r.Get("/admin/logs/stats", s.apiLogStats)
		r.Delete("/admin/logs", s.cleanupAPILogs)
	})

	if s.uiHandler != nil {
		r.Handle("/*", s.uiHandler)
	}
	return r
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context, onReady func()) error {
	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(s.cfg.ServerPort),
		Handler:           s.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		errCh <- err
	}()
	onReady()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// metricsMiddleware records HTTP request counts, durations, and api_logs rows.
func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		excluded := isExcludedPath(r.URL.Path)
		audit := !excluded && shouldAuditLog(r.URL.Path)
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if excluded {
			return
		}
		if s.metrics != nil {
			s.metrics.HTTPRequests.WithLabelValues(r.Method, strconv.Itoa(rec.status)).Inc()
			s.metrics.HTTPRequestDuration.WithLabelValues(r.Method).Observe(time.Since(start).Seconds())
		}
		if audit && s.audit != nil {
			entry := model.APILogEntry{
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: rec.status,
				DurationMS: int(time.Since(start).Milliseconds()),
				RemoteAddr: clientIP(r),
				UserAgent:  r.UserAgent(),
			}
			// Best-effort; audit logging must not break requests.
			_ = s.audit.InsertAPILog(context.Background(), entry)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func isExcludedPath(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/metrics":
		return true
	}
	return len(path) >= 8 && path[:8] == "/assets/"
}
