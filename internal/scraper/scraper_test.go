package scraper

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/model"
	"github.com/duynhlab/trivy-viewer/internal/watcher"
)

// fakeWriter records store calls; failEvery > 0 makes every Nth upsert fail.
type fakeWriter struct {
	mu        sync.Mutex
	upserts   []model.Report
	deletes   []string
	failEvery int
	calls     int
}

func (f *fakeWriter) UpsertReport(_ context.Context, rep model.Report) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failEvery > 0 && f.calls%f.failEvery == 0 {
		return errors.New("injected store failure")
	}
	f.upserts = append(f.upserts, rep)
	return nil
}

func (f *fakeWriter) DeleteReport(_ context.Context, cluster, namespace, name, reportType string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, cluster+"/"+namespace+"/"+name+"/"+reportType)
	return nil
}

func (f *fakeWriter) DeleteByCluster(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (f *fakeWriter) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.upserts), len(f.deletes)
}

// waitFor polls cond until it holds or the deadline expires.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", msg)
}

func upsertEvent(cluster, name string) watcher.Event {
	return watcher.Event{
		Type: watcher.EventUpsert,
		Report: model.Report{
			Cluster: cluster, Namespace: "default", Name: name,
			ReportType: model.ReportTypeVuln, Data: "{}",
		},
	}
}

func TestPipelineProcessesUpsertsAndDeletes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &fakeWriter{}
	p := startPipeline(ctx, store, nil)
	h := p.handler(ctx)

	for i := range 10 {
		h(upsertEvent("edge-a", fmt.Sprintf("rep-%d", i)))
	}
	h(watcher.Event{
		Type:    watcher.EventDelete,
		Cluster: "edge-a", Namespace: "default", Name: "rep-0", ReportType: model.ReportTypeVuln,
	})

	waitFor(t, func() bool {
		u, d := store.counts()
		return u == 10 && d == 1
	}, "10 upserts + 1 delete")

	cancel()
	p.wait() // must return: workers exit on ctx.Done
}

func TestPipelineWorkerSurvivesStoreErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &fakeWriter{failEvery: 2} // every 2nd upsert fails
	p := startPipeline(ctx, store, nil)
	h := p.handler(ctx)

	for i := range 6 {
		h(upsertEvent("edge-b", fmt.Sprintf("rep-%d", i)))
	}

	// 3 of 6 fail; workers must log and continue, not die.
	waitFor(t, func() bool {
		u, _ := store.counts()
		return u == 3
	}, "3 surviving upserts")

	cancel()
	p.wait()
}

func TestPipelineHandlerSafeAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	store := &fakeWriter{}
	p := startPipeline(ctx, store, nil)
	h := p.handler(ctx)

	cancel()
	p.wait()

	// A straggler informer callback after shutdown must neither panic nor
	// block, even with the buffer full. This is the regression test for the
	// send-on-closed-channel window removed from Run.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range eventBuffer + 10 {
			h(upsertEvent("late", fmt.Sprintf("rep-%d", i)))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("late handler calls blocked after cancel")
	}
}

func TestPipelineBackpressureBeyondBuffer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &fakeWriter{}
	p := startPipeline(ctx, store, nil)
	h := p.handler(ctx)

	total := eventBuffer + 200 // force producers to block on a full buffer
	var producers sync.WaitGroup
	for g := range 4 {
		producers.Go(func() {
			for i := range total / 4 {
				h(upsertEvent("edge-c", fmt.Sprintf("g%d-rep-%d", g, i)))
			}
		})
	}
	producers.Wait()

	waitFor(t, func() bool {
		u, _ := store.counts()
		return u == total
	}, "all events drained through full buffer")

	cancel()
	p.wait()
}
