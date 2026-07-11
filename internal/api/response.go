package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// Default values for handler query parameters, shared across endpoints.
const (
	defaultSearchLimit      = 100
	defaultSuggestLimit     = 10
	defaultLogPageLimit     = 50
	defaultLogRetentionDays = 7
)

// errorBody is the JSON error shape the frontend reads (`body.error`).
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response failed", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// notImplemented responds 501 for endpoints deferred to v2 (alerts, admin logs,
// OIDC). Returning a clear message keeps the UI predictable (see ADR-002).
func notImplemented(feature string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotImplemented, feature+" is not available in this build (v1 scope)")
	}
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
