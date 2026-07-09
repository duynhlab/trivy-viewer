// Package buildinfo holds build-time metadata injected via -ldflags.
package buildinfo

// These are overridden at build time, e.g.:
//
//	go build -ldflags "-X github.com/duynhlab/trivy-viewer/internal/buildinfo.Version=1.0.0 ..."
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
