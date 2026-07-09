package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesIndex(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/ status = %d", rec.Code)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "<html") {
		t.Errorf("expected HTML from index, got %q", rec.Body.String())
	}
}

func TestHandlerSPAFallback(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/clusters/deep/route", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("SPA fallback status = %d, want 200", rec.Code)
	}
}
