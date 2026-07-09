package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

// EventType distinguishes report upserts from deletions.
type EventType string

const (
	// EventUpsert means a report was added or updated.
	EventUpsert EventType = "upsert"
	// EventDelete means a report was removed.
	EventDelete EventType = "delete"
)

// Event is emitted by the watcher for each observed report change.
type Event struct {
	Type       EventType
	Report     model.Report // populated for EventUpsert
	Cluster    string
	Namespace  string
	Name       string
	ReportType string
}

// Handler consumes watcher events (typically enqueues onto a worker pool).
type Handler func(Event)

// Watcher runs dynamic informers over the Trivy CRDs in one cluster and emits
// normalized events. Reports are tagged with the given cluster name.
type Watcher struct {
	client     dynamic.Interface
	cluster    string
	namespaces []string
	handler    Handler

	// OnEvent is an optional metrics hook (reportType, eventType).
	OnEvent func(reportType, eventType string)
}

// New builds a watcher. An empty namespaces slice watches all namespaces.
func New(client dynamic.Interface, cluster string, namespaces []string, handler Handler) *Watcher {
	return &Watcher{client: client, cluster: cluster, namespaces: namespaces, handler: handler}
}

// Run starts informers and blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	nss := w.namespaces
	if len(nss) == 0 {
		nss = []string{metav1.NamespaceAll}
	}

	for _, ns := range nss {
		factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(w.client, 10*time.Minute, ns, nil)
		for _, gvr := range []schema.GroupVersionResource{VulnGVR, SbomGVR} {
			if err := w.addInformer(factory, gvr); err != nil {
				return err
			}
		}
		factory.Start(ctx.Done())
		synced := factory.WaitForCacheSync(ctx.Done())
		for typ, ok := range synced {
			if !ok {
				return fmt.Errorf("cache sync failed for %s in namespace %q", typ, ns)
			}
		}
		slog.Info("watcher started", "cluster", w.cluster, "namespace", ns)
	}

	<-ctx.Done()
	return nil
}

func (w *Watcher) addInformer(factory dynamicinformer.DynamicSharedInformerFactory, gvr schema.GroupVersionResource) error {
	reportType := reportTypeForGVR(gvr)
	informer := factory.ForResource(gvr).Informer()
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			w.emitUpsert(reportType, obj)
			w.metric(reportType, "apply")
		},
		UpdateFunc: func(_, newObj any) {
			w.emitUpsert(reportType, newObj)
			w.metric(reportType, "apply")
		},
		DeleteFunc: func(obj any) {
			w.emitDelete(reportType, obj)
			w.metric(reportType, "delete")
		},
	})
	if err != nil {
		return fmt.Errorf("add event handler for %s: %w", gvr.Resource, err)
	}
	return nil
}

func (w *Watcher) emitUpsert(reportType string, obj any) {
	u, ok := toUnstructured(obj)
	if !ok {
		return
	}
	rep, err := Normalize(w.cluster, reportType, u.Object)
	if err != nil {
		slog.Warn("skip malformed report", "cluster", w.cluster, "error", err)
		return
	}
	w.handler(Event{Type: EventUpsert, Report: rep})
}

func (w *Watcher) emitDelete(reportType string, obj any) {
	u, ok := toUnstructured(obj)
	if !ok {
		return
	}
	w.handler(Event{
		Type:       EventDelete,
		Cluster:    w.cluster,
		Namespace:  u.GetNamespace(),
		Name:       u.GetName(),
		ReportType: reportType,
	})
}

func (w *Watcher) metric(reportType, event string) {
	if w.OnEvent != nil {
		w.OnEvent(reportType, event)
	}
}

// toUnstructured unwraps an informer object, handling tombstones on delete.
func toUnstructured(obj any) (*unstructured.Unstructured, bool) {
	switch v := obj.(type) {
	case *unstructured.Unstructured:
		return v, true
	case cache.DeletedFinalStateUnknown:
		if u, ok := v.Obj.(*unstructured.Unstructured); ok {
			return u, true
		}
	}
	return nil, false
}
