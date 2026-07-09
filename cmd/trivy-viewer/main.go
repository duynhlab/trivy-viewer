// Command trivy-viewer is a single binary that runs as one of two modes:
// --mode=server (UI/API) or --mode=scraper (watchers). The mode maps to the two
// Deployments created by the Helm chart on the central Hub cluster.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/duynhlab/trivy-viewer/internal/buildinfo"
	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/duynhlab/trivy-viewer/internal/health"
	"github.com/duynhlab/trivy-viewer/internal/logging"
	"github.com/duynhlab/trivy-viewer/internal/metrics"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var mode string

	root := &cobra.Command{
		Use:           "trivy-viewer",
		Short:         "Multi-cluster Trivy report collector and viewer",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(os.Getenv, mode)
			if err != nil {
				return err
			}
			return run(cmd.Context(), cfg)
		},
	}
	root.PersistentFlags().StringVar(&mode, "mode", "", "deployment mode: server|scraper (overrides MODE env)")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("trivy-viewer %s (commit %s, built %s)\n",
				buildinfo.Version, buildinfo.Commit, buildinfo.BuildDate)
		},
	})
	return root
}

func run(ctx context.Context, cfg *config.Config) error {
	logging.Init(cfg.LogFormat, cfg.LogLevel)
	slog.Info("starting trivy-viewer",
		"version", buildinfo.Version,
		"commit", buildinfo.Commit,
		"mode", cfg.Mode,
	)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := metrics.New(cfg.Mode, buildinfo.Version)
	h := health.New(m.Handler())

	healthAddr := fmt.Sprintf(":%d", cfg.HealthPort)
	healthErr := make(chan error, 1)
	go func() { healthErr <- h.Serve(ctx, healthAddr) }()
	slog.Info("health server listening", "addr", healthAddr, "endpoints", "/healthz /readyz /metrics")

	var runErr error
	switch cfg.Mode {
	case config.ModeScraper:
		runErr = runScraper(ctx, cfg, m, h)
	case config.ModeServer:
		runErr = runServer(ctx, cfg, m, h)
	}

	stop()
	if err := <-healthErr; err != nil {
		slog.Error("health server error", "error", err)
	}
	return runErr
}
