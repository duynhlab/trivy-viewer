package main

import (
	"context"
	"log/slog"

	"github.com/duynhlab/trivy-viewer/internal/api"
	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/duynhlab/trivy-viewer/internal/health"
	"github.com/duynhlab/trivy-viewer/internal/kube"
	"github.com/duynhlab/trivy-viewer/internal/metrics"
	"github.com/duynhlab/trivy-viewer/internal/scraper"
	"github.com/duynhlab/trivy-viewer/internal/storage"
	"github.com/duynhlab/trivy-viewer/internal/web"
	"k8s.io/client-go/kubernetes"
)

func runScraper(ctx context.Context, cfg *config.Config, m *metrics.Metrics, h *health.Server) error {
	db, err := storage.Open(ctx, cfg.StoragePath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	repo := storage.NewRepository(db)

	return scraper.Run(ctx, cfg, repo, m, func() { h.SetReady(true) })
}

func runServer(ctx context.Context, cfg *config.Config, m *metrics.Metrics, h *health.Server) error {
	db, err := storage.Open(ctx, cfg.StoragePath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	repo := storage.NewRepository(db)

	ui, err := web.Handler()
	if err != nil {
		return err
	}

	// Kubernetes access powers cluster-registration endpoints. It is optional:
	// without it the UI still works and those endpoints fail with a clear message.
	var kubeClient kubernetes.Interface
	hubNamespace := ""
	if typed, _, err := kube.Clients(); err != nil {
		slog.Warn("no Kubernetes access; cluster registration endpoints disabled", "error", err)
	} else {
		kubeClient = typed
		hubNamespace = kube.CurrentNamespace(cfg.HubSecretNamespace)
	}

	srv := api.New(api.Options{
		Repo:         repo,
		Config:       cfg,
		Metrics:      m,
		DBPath:       db.Path(),
		Kube:         kubeClient,
		HubNamespace: hubNamespace,
		UIHandler:    ui,
	})
	return srv.Run(ctx, func() { h.SetReady(true) })
}
