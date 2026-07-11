package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/duynhlab/trivy-viewer/internal/model"
)

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{5 * 1024 * 1024 * 1024, "5.0 GiB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		xff        string
		xRealIP    string
		remoteAddr string
		want       string
	}{
		{"x-forwarded-for single", "10.0.0.1", "", "127.0.0.1:1234", "10.0.0.1"},
		{"x-forwarded-for chain takes first", "10.0.0.1, 192.168.0.1", "", "127.0.0.1:1234", "10.0.0.1"},
		{"x-forwarded-for trims spaces", "  10.0.0.2 , 172.16.0.1", "", "127.0.0.1:1234", "10.0.0.2"},
		{"x-real-ip fallback", "", "10.9.8.7", "127.0.0.1:1234", "10.9.8.7"},
		{"remote addr host:port", "", "", "192.168.1.5:9999", "192.168.1.5"},
		{"remote addr without port", "", "", "192.168.1.5", "192.168.1.5"},
		{"xff wins over x-real-ip", "1.1.1.1", "2.2.2.2", "3.3.3.3:1", "1.1.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				r.Header.Set("X-Real-IP", tc.xRealIP)
			}
			if got := clientIP(r); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTrendsClusterFilter(t *testing.T) {
	srv, repo := newTestServer(t)
	seedReport(t, repo, model.Report{
		Cluster: "hub", Namespace: "a", Name: "r1", ReportType: model.ReportTypeVuln,
		Critical: 5, Data: `{}`,
	})
	seedReport(t, repo, model.Report{
		Cluster: "edge", Namespace: "a", Name: "r2", ReportType: model.ReportTypeVuln,
		Critical: 2, Data: `{}`,
	})

	var resp struct {
		Series []struct {
			Critical      int64 `json:"critical"`
			VulnReports   int64 `json:"vuln_reports"`
			ClustersCount int64 `json:"clusters_count"`
		} `json:"series"`
	}

	rec := do(t, srv, http.MethodGet, "/api/v1/dashboard/trends?range=1d&cluster=hub")
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Series) != 1 {
		t.Fatalf("decode: err=%v body=%s", err, rec.Body.String())
	}
	if resp.Series[0].Critical != 5 || resp.Series[0].VulnReports != 1 || resp.Series[0].ClustersCount != 1 {
		t.Errorf("filtered series = %+v, want hub-only (critical 5, 1 report, 1 cluster)", resp.Series[0])
	}

	rec = do(t, srv, http.MethodGet, "/api/v1/dashboard/trends?range=1d")
	resp.Series = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Series) != 1 || resp.Series[0].Critical != 7 || resp.Series[0].ClustersCount != 2 {
		t.Errorf("unfiltered series = %+v, want totals (critical 7, 2 clusters)", resp.Series)
	}
}
