// Package health runs the auxiliary HTTP server that exposes liveness,
// readiness, and Prometheus metrics. It shares one port across all three so no
// extra port is required (matches upstream).
package health

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// Server serves /healthz, /readyz and /metrics.
type Server struct {
	ready   atomic.Bool
	metrics http.Handler
}

// New creates a health server. The metrics handler may be nil.
func New(metrics http.Handler) *Server {
	return &Server{metrics: metrics}
}

// SetReady flips the readiness state reported by /readyz.
func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

// Handler returns the mux serving the health endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	if s.metrics != nil {
		mux.Handle("/metrics", s.metrics)
	}
	return mux
}

// Serve runs the health server until the context is cancelled, then shuts down
// gracefully. It returns nil on a clean shutdown.
func (s *Server) Serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
