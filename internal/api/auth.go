package api

import "net/http"

// authMe returns a permissive identity under auth: none so the UI renders admin
// controls. When OIDC lands (v2) this reflects the real session.
func (s *Server) authMe(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"auth_mode":     "none",
		"permissions": map[string]bool{
			"can_admin":          true,
			"can_delete_reports": true,
			"can_manage_tokens":  false,
			"can_manage_alerts":  false,
			"can_view_alerts":    false,
			"can_view_clusters":  true,
		},
	})
}

// authTokens returns an empty token list (API tokens are a v2 feature).
func (s *Server) authTokens(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tokens": []any{}})
}
