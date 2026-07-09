// Package logging configures the process-wide slog logger.
package logging

import (
	"log/slog"
	"os"
)

// Init sets the default slog logger based on format ("json" or "pretty") and
// level ("debug"|"info"|"warn"|"error").
func Init(format, level string) {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}

	var handler slog.Handler
	if format == "pretty" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
