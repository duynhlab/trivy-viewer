// Package scraper wires the watcher stack for scraper mode: a local watcher for
// the Hub's own cluster plus a Secret-driven manager that attaches a watcher to
// each registered Edge cluster. All events flow through a worker pool into the
// report store (watchers never write to the DB directly; see docs/08-concurrency.md).
package scraper

import (
	"context"
	"log/slog"
	"sync"

	"github.com/duynhlab/trivy-viewer/internal/config"
	"github.com/duynhlab/trivy-viewer/internal/hub"
	"github.com/duynhlab/trivy-viewer/internal/kube"
	"github.com/duynhlab/trivy-viewer/internal/metrics"
	"github.com/duynhlab/trivy-viewer/internal/model"
	"github.com/duynhlab/trivy-viewer/internal/watcher"
)

const (
	eventBuffer = 1024
	workerCount = 4
)

// ReportWriter is the subset of the report store the scraper writes through.
type ReportWriter interface {
	UpsertReport(ctx context.Context, rep model.Report) error
	DeleteReport(ctx context.Context, cluster, namespace, name, reportType string) error
	DeleteByCluster(ctx context.Context, cluster string) (int64, error)
}

// pipeline connects watcher callbacks to the store: a buffered channel drained
// by a fixed worker pool. It is the unit under test; Run only adds kube wiring.
type pipeline struct {
	events chan watcher.Event
	wg     sync.WaitGroup
}

// startPipeline spawns the worker pool. Workers exit when ctx is cancelled;
// call wait to join them.
func startPipeline(ctx context.Context, store ReportWriter, m *metrics.Metrics) *pipeline {
	p := &pipeline{events: make(chan watcher.Event, eventBuffer)}
	for range workerCount {
		p.wg.Go(func() {
			worker(ctx, p.events, store, m)
		})
	}
	return p
}

// handler returns the watcher.Handler feeding this pipeline. After ctx is
// cancelled, sends are abandoned so late informer callbacks never block or
// panic. The events channel is intentionally never closed (see
// docs/08-concurrency.md).
func (p *pipeline) handler(ctx context.Context) watcher.Handler {
	return func(e watcher.Event) {
		select {
		case p.events <- e:
		case <-ctx.Done():
		}
	}
}

func (p *pipeline) wait() { p.wg.Wait() }

// Run starts the scraper. It blocks until ctx is cancelled. onReady is invoked
// once the watchers are attached so the caller can flip readiness.
func Run(ctx context.Context, cfg *config.Config, store ReportWriter, m *metrics.Metrics, onReady func()) error {
	typed, dyn, err := kube.Clients()
	if err != nil {
		return err
	}
	namespace := kube.CurrentNamespace(cfg.HubSecretNamespace)

	p := startPipeline(ctx, store, m)
	handler := p.handler(ctx)

	// Local watcher for the Hub's own cluster.
	var watchers sync.WaitGroup
	if cfg.WatchLocal {
		lw := watcher.New(dyn, cfg.ClusterName, cfg.Namespaces, handler)
		lw.OnEvent = metricEvent(m)
		watchers.Go(func() {
			if err := lw.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Error("local watcher stopped", "error", err)
			}
		})
		slog.Info("local watcher enabled", "cluster", cfg.ClusterName)
	}

	// Hub Secret watcher + per-cluster watchers.
	mgr := hub.NewManager(typed, namespace, handler, nil)
	mgr.OnPurge = func(purgeCtx context.Context, cluster string) {
		n, err := store.DeleteByCluster(purgeCtx, cluster)
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
	// manager (which cancels every per-cluster watcher), then the local
	// watcher and the workers drain. Events still buffered at this point are
	// dropped by design — informers are level-triggered, so the next start
	// repopulates them via the initial list.
	<-ctx.Done()
	err = <-mgrDone
	watchers.Wait()
	p.wait()
	return err
}

func worker(ctx context.Context, events <-chan watcher.Event, store ReportWriter, m *metrics.Metrics) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			process(ctx, e, store, m)
		}
	}
}

func process(ctx context.Context, e watcher.Event, store ReportWriter, m *metrics.Metrics) {
	switch e.Type {
	case watcher.EventUpsert:
		if err := store.UpsertReport(ctx, e.Report); err != nil {
			slog.Error("store report failed", "cluster", e.Report.Cluster, "name", e.Report.Name, "error", err)
			return
		}
		if m != nil {
			m.ReportsStored.WithLabelValues(e.Report.Cluster, e.Report.ReportType).Inc()
		}
	case watcher.EventDelete:
		if err := store.DeleteReport(ctx, e.Cluster, e.Namespace, e.Name, e.ReportType); err != nil {
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
