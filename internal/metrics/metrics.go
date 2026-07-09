// Package metrics defines the Prometheus metrics for both modes. Metric names
// follow the upstream implementation where practical so existing dashboards can
// be reused. Counters are pre-initialized to zero so time series exist from the
// first scrape (no "No data" panels).
package metrics

import (
	"net/http"

	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "trivy_viewer"

// Metrics owns a registry and the metric handles used across the app.
type Metrics struct {
	reg *prometheus.Registry

	// Common.
	Info *prometheus.GaugeVec

	// Server mode.
	HTTPRequests        *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	DBSizeBytes         prometheus.Gauge
	DBReportsTotal      *prometheus.GaugeVec

	// Scraper mode.
	WatcherEvents   *prometheus.CounterVec
	WatchedClusters prometheus.Gauge
	ReportsStored   *prometheus.CounterVec
	DBWriteDuration prometheus.Histogram
}

// New builds a registry and registers the metrics relevant to the given mode.
func New(mode config.Mode, version string) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}

	m.Info = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "info",
		Help:      "Build information (always 1).",
	}, []string{"version", "mode"})
	reg.MustRegister(m.Info)
	m.Info.WithLabelValues(version, string(mode)).Set(1)

	switch mode {
	case config.ModeServer:
		m.registerServer(reg)
	case config.ModeScraper:
		m.registerScraper(reg)
	}
	return m
}

func (m *Metrics) registerServer(reg *prometheus.Registry) {
	m.HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "http_requests_total",
		Help:      "Total HTTP requests.",
	}, []string{"method", "status"})

	m.HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request duration in seconds.",
		Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"method"})

	m.DBSizeBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "db_size_bytes",
		Help:      "SQLite database file size in bytes.",
	})

	m.DBReportsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "db_reports_total",
		Help:      "Stored report count per type.",
	}, []string{"report_type"})

	reg.MustRegister(m.HTTPRequests, m.HTTPRequestDuration, m.DBSizeBytes, m.DBReportsTotal)
}

func (m *Metrics) registerScraper(reg *prometheus.Registry) {
	m.WatcherEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "watcher_events_total",
		Help:      "Kubernetes watcher events.",
	}, []string{"report_type", "event_type"})

	m.WatchedClusters = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "watched_clusters",
		Help:      "Number of active per-cluster watchers.",
	})

	m.ReportsStored = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "reports_stored_total",
		Help:      "Reports written to the database.",
	}, []string{"cluster", "report_type"})

	m.DBWriteDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "db_write_duration_seconds",
		Help:      "Repository write latency in seconds.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	})

	reg.MustRegister(m.WatcherEvents, m.WatchedClusters, m.ReportsStored, m.DBWriteDuration)
}

// Handler returns the HTTP handler serving the registry at /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Registry exposes the underlying registry (for tests).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }
