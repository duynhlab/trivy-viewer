package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/config"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d", rec.Code)
	}
	return rec.Body.String()
}

func TestServerModeRegistersHTTPMetrics(t *testing.T) {
	m := New(config.ModeServer, "1.2.3")
	m.HTTPRequests.WithLabelValues("GET", "200").Inc()
	body := scrape(t, m)
	for _, want := range []string{"trivy_viewer_info", "trivy_viewer_http_requests_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("server metrics missing %q", want)
		}
	}
	if strings.Contains(body, "trivy_viewer_watcher_events_total") {
		t.Errorf("server mode should not register scraper metrics")
	}
}

func TestScraperModeRegistersWatcherMetrics(t *testing.T) {
	m := New(config.ModeScraper, "1.2.3")
	m.WatcherEvents.WithLabelValues("vulnerabilityreport", "apply").Inc()
	body := scrape(t, m)
	for _, want := range []string{"trivy_viewer_info", "trivy_viewer_watcher_events_total", "trivy_viewer_watched_clusters"} {
		if !strings.Contains(body, want) {
			t.Errorf("scraper metrics missing %q", want)
		}
	}
}
