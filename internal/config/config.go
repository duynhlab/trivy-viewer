// Package config parses and validates runtime configuration from environment
// variables. Variable names mirror the upstream Rust implementation so operators
// and the Helm chart stay compatible across the two runtimes.
package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Mode is the deployment role. A single binary runs as one of two pods.
type Mode string

const (
	// ModeServer serves the UI and REST API and reads the shared SQLite DB.
	ModeServer Mode = "server"
	// ModeScraper runs the watchers and writes to the shared SQLite DB.
	ModeScraper Mode = "scraper"
)

// Environment variable names. Kept in one place so config parsing and any
// API that echoes effective config agree on the spelling.
const (
	EnvMode               = "MODE"
	EnvLogFormat          = "LOG_FORMAT"
	EnvLogLevel           = "LOG_LEVEL"
	EnvHealthPort         = "HEALTH_PORT"
	EnvServerPort         = "SERVER_PORT"
	EnvStoragePath        = "STORAGE_PATH"
	EnvAuthMode           = "AUTH_MODE"
	EnvClusterName        = "CLUSTER_NAME"
	EnvWatchLocal         = "WATCH_LOCAL"
	EnvHubSecretNamespace = "HUB_SECRET_NAMESPACE"
	EnvNamespaces         = "NAMESPACES"
	EnvExternalURL        = "EXTERNAL_URL"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	Mode       Mode
	LogFormat  string // "json" or "pretty"
	LogLevel   string // "debug" | "info" | "warn" | "error"
	HealthPort int

	// Server mode.
	ServerPort  int
	StoragePath string
	AuthMode    string // v1: only "none"
	ExternalURL string

	// Scraper mode.
	ClusterName        string
	WatchLocal         bool
	HubSecretNamespace string
	Namespaces         []string
}

// Load builds a Config from the given getenv function and an optional mode
// override (e.g. from a --mode flag). Passing getenv explicitly keeps this
// pure and testable. An empty modeOverride falls back to the MODE env var.
func Load(getenv func(string) string, modeOverride string) (*Config, error) {
	c := &Config{
		Mode:               Mode(firstNonEmpty(modeOverride, getenv(EnvMode), string(ModeServer))),
		LogFormat:          firstNonEmpty(getenv(EnvLogFormat), "json"),
		LogLevel:           firstNonEmpty(getenv(EnvLogLevel), "info"),
		ServerPort:         3000,
		StoragePath:        firstNonEmpty(getenv(EnvStoragePath), "/data"),
		AuthMode:           firstNonEmpty(getenv(EnvAuthMode), "none"),
		ExternalURL:        getenv(EnvExternalURL),
		ClusterName:        firstNonEmpty(getenv(EnvClusterName), "local"),
		HubSecretNamespace: getenv(EnvHubSecretNamespace),
		WatchLocal:         parseBool(getenv(EnvWatchLocal), true),
		Namespaces:         parseCSV(getenv(EnvNamespaces)),
	}

	healthPort, err := parsePort(getenv(EnvHealthPort), 8080)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvHealthPort, err)
	}
	c.HealthPort = healthPort

	serverPort, err := parsePort(getenv(EnvServerPort), 3000)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvServerPort, err)
	}
	c.ServerPort = serverPort

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks mode-specific invariants.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeServer, ModeScraper:
	default:
		return fmt.Errorf("invalid MODE %q: must be %q or %q", c.Mode, ModeServer, ModeScraper)
	}

	switch c.LogFormat {
	case "json", "pretty":
	default:
		return fmt.Errorf("invalid LOG_FORMAT %q: must be \"json\" or \"pretty\"", c.LogFormat)
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid LOG_LEVEL %q: must be debug|info|warn|error", c.LogLevel)
	}

	if c.StoragePath == "" {
		return fmt.Errorf("STORAGE_PATH must not be empty")
	}

	// v1 only supports auth_mode=none; guard against silent misconfiguration.
	if c.Mode == ModeServer && c.AuthMode != "none" {
		return fmt.Errorf("AUTH_MODE %q not supported in v1: only \"none\"", c.AuthMode)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseBool(v string, def bool) bool {
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func parseCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePort(v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	p, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", v, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", p)
	}
	return p, nil
}
