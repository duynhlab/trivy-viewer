// Package web embeds the built frontend and serves it with SPA fallback. The
// upstream React app is vendored under frontend/ and built into static/ by
// `make frontend` (see docs/06-ui.md). A placeholder index.html is checked in so
// the package compiles before the frontend is built.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:static
var staticFS embed.FS

// Handler returns an http.Handler serving the embedded frontend. Requests for
// existing files are served directly; any other non-API path falls back to
// index.html so client-side routing works.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := sub.Open(p); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	}), nil
}
