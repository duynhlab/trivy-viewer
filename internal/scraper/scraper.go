// Package scraper wires the watcher stack for scraper mode: a local watcher for
// the Hub's own cluster plus a Secret-driven manager that attaches a watcher to
// each registered Edge cluster. All events flow through a worker pool into the
// repository (watchers never write to the DB directly; see docs/08-concurrency.md).
package scraper

import (
	"context"
	"log/slog"
	"sync"

	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/duynhlab/trivy-viewer/internal/hub"
	"github.com/duynhlab/trivy-viewer/internal/kube"
	"github.com/duynhlab/trivy-viewer/internal/metrics"
	"github.com/duynhlab/trivy-viewer/internal/storage"
	"github.com/duynhlab/trivy-viewer/internal/watcher"
)

const (
	eventBuffer = 1024
	workerCount = 4
)

// Run starts the scraper. It blocks until ctx is cancelled. onReady is invoked
// once the watchers are attached so the caller can flip readiness.
func Run(ctx context.Context, cfg *config.Config, repo *storage.Repository, m *metrics.Metrics, onReady func()) error {
	typed, dyn, err := kube.Clients()
	if err != nil {
		return err
	}
	namespace := kube.CurrentNamespace(cfg.HubSecretNamespace)

	events := make(chan watcher.Event, eventBuffer)
	handler := func(e watcher.Event) {
		select {
		case events <- e:
		case <-ctx.Done():
		}
	}

	var wg sync.WaitGroup
	for range workerCount {
		wg.Go(func() {
			worker(ctx, events, repo, m)
		})
	}

	// Local watcher for the Hub's own cluster.
	if cfg.WatchLocal {
		lw := watcher.New(dyn, cfg.ClusterName, cfg.Namespaces, handler)
		lw.OnEvent = metricEvent(m)
		wg.Go(func() {
			if err := lw.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Error("local watcher stopped", "error", err)
			}
		})
		slog.Info("local watcher enabled", "cluster", cfg.ClusterName)
	}

	// Hub Secret watcher + per-cluster watchers.
	mgr := hub.NewManager(typed, namespace, handler, nil)
	mgr.OnPurge = func(purgeCtx context.Context, cluster string) {
		n, err := repo.DeleteByCluster(purgeCtx, cluster)
		if err != nil {
			slog.Error("purge cluster reports failed", "cluster", cluster, "error", err)
			return
		}
		slog.Info("purged cluster reports", "cluster", cluster, "deleted", n)
	}
	if m != nil {
		mgr.OnWatchedCount = func(n int) { m.WatchedClusters.Set(float64(n)) }
		mgr.OnEvent = metricEvent(m)
	}

	mgrDone := make(chan error, 1)
	go func() { mgrDone <- mgr.Run(ctx) }()

	onReady()
	slog.Info("scraper ready", "hub_namespace", namespace, "watch_local", cfg.WatchLocal)

	// Shutdown ordering (see docs/08-concurrency.md): ctx cancel stops the
	// manager (which cancels every per-cluster watcher), then we wait for the
	// local watcher and the workers to drain. The events channel is never
	// closed: informer callbacks stop asynchronously after cancellation and a
	// straggler could otherwise send on a closed channel and panic. Events
	// still buffered at this point are dropped by design — informers are
	// level-triggered, so the next start repopulates them via the initial list.
	<-ctx.Done()
	err = <-mgrDone
	wg.Wait()
	return err
}

func worker(ctx context.Context, events <-chan watcher.Event, repo *storage.Repository, m *metrics.Metrics) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			process(ctx, e, repo, m)
		}
	}
}

func process(ctx context.Context, e watcher.Event, repo *storage.Repository, m *metrics.Metrics) {
	switch e.Type {
	case watcher.EventUpsert:
		if err := repo.UpsertReport(ctx, e.Report); err != nil {
			slog.Error("store report failed", "cluster", e.Report.Cluster, "name", e.Report.Name, "error", err)
			return
		}
		if m != nil {
			m.ReportsStored.WithLabelValues(e.Report.Cluster, e.Report.ReportType).Inc()
		}
	case watcher.EventDelete:
		if err := repo.DeleteReport(ctx, e.Cluster, e.Namespace, e.Name, e.ReportType); err != nil {
			slog.Error("delete report failed", "cluster", e.Cluster, "name", e.Name, "error", err)
		}
	}
}

func metricEvent(m *metrics.Metrics) func(string, string) {
	if m == nil {
		return nil
	}
	return func(reportType, eventType string) {
		m.WatcherEvents.WithLabelValues(reportType, eventType).Inc()
	}
}
