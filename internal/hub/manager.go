package hub

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/watcher"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// ClientFactory builds a dynamic client for a cluster config. Injectable so the
// manager can be unit-tested with a fake client.
type ClientFactory func(ClusterConfig) (dynamic.Interface, error)

// Manager watches cluster-registration Secrets and maintains one watcher per
// registered cluster. Adding a Secret spawns a watcher; deleting it stops the
// watcher and purges that cluster's reports.
type Manager struct {
	kube      kubernetes.Interface
	namespace string
	handler   watcher.Handler
	newClient ClientFactory

	// OnPurge is called with a cluster name when its Secret is deleted.
	OnPurge func(ctx context.Context, cluster string)
	// OnWatchedCount reports the number of active per-cluster watchers.
	OnWatchedCount func(int)
	// OnEvent forwards watcher metric events (reportType, eventType).
	OnEvent func(reportType, eventType string)

	mu        sync.Mutex
	active    map[string]*clusterWatch
	parentCtx context.Context
}

type clusterWatch struct {
	cancel          context.CancelFunc
	clusterName     string
	resourceVersion string
}

// NewManager builds a Manager. namespace is the Hub namespace holding the
// cluster Secrets. newClient may be nil to use the default builder.
func NewManager(kube kubernetes.Interface, namespace string, handler watcher.Handler, newClient ClientFactory) *Manager {
	if newClient == nil {
		newClient = BuildDynamicClient
	}
	return &Manager{
		kube:      kube,
		namespace: namespace,
		handler:   handler,
		newClient: newClient,
		active:    make(map[string]*clusterWatch),
	}
}

// Run starts the Secret informer and blocks until ctx is cancelled, then stops
// all per-cluster watchers.
func (m *Manager) Run(ctx context.Context) error {
	m.parentCtx = ctx

	factory := informers.NewSharedInformerFactoryWithOptions(
		m.kube, 10*time.Minute,
		informers.WithNamespace(m.namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = SecretTypeLabelKey + "=" + SecretTypeCluster
		}),
	)
	informer := factory.Core().V1().Secrets().Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { m.upsert(secretOf(obj)) },
		UpdateFunc: func(_, newObj any) { m.upsert(secretOf(newObj)) },
		DeleteFunc: func(obj any) { m.remove(secretOf(obj)) },
	}); err != nil {
		return fmt.Errorf("add secret event handler: %w", err)
	}

	factory.Start(ctx.Done())
	for typ, ok := range factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("secret cache sync failed for %v", typ)
		}
	}
	slog.Info("hub secret watcher started", "namespace", m.namespace)

	<-ctx.Done()
	m.stopAll()
	return nil
}

func (m *Manager) upsert(s *corev1.Secret) {
	if s == nil {
		return
	}
	key := s.Namespace + "/" + s.Name

	m.mu.Lock()
	if cw, ok := m.active[key]; ok && cw.resourceVersion == s.ResourceVersion {
		m.mu.Unlock() // unchanged (informer resync); nothing to do
		return
	}
	m.mu.Unlock()

	cfg, err := ParseClusterSecret(s)
	if err != nil {
		slog.Warn("skip invalid cluster secret", "key", key, "error", err)
		return
	}
	client, err := m.newClient(cfg)
	if err != nil {
		slog.Error("build cluster client failed", "cluster", cfg.Name, "error", err)
		return
	}

	m.mu.Lock()
	if cw, ok := m.active[key]; ok {
		cw.cancel() // restart to pick up token/CA/server changes
		delete(m.active, key)
	}
	wctx, cancel := context.WithCancel(m.parentCtx)
	m.active[key] = &clusterWatch{cancel: cancel, clusterName: cfg.Name, resourceVersion: s.ResourceVersion}
	count := len(m.active)
	m.mu.Unlock()
	m.reportCount(count)

	w := watcher.New(client, cfg.Name, cfg.Namespaces, m.handler)
	w.OnEvent = m.OnEvent
	slog.Info("attaching per-cluster watcher", "cluster", cfg.Name, "server", cfg.Server)
	go func() {
		if err := w.Run(wctx); err != nil && wctx.Err() == nil {
			slog.Error("per-cluster watcher stopped", "cluster", cfg.Name, "error", err)
		}
	}()
}

func (m *Manager) remove(s *corev1.Secret) {
	if s == nil {
		return
	}
	key := s.Namespace + "/" + s.Name

	m.mu.Lock()
	cw, ok := m.active[key]
	if ok {
		cw.cancel()
		delete(m.active, key)
	}
	count := len(m.active)
	m.mu.Unlock()

	if !ok {
		return
	}
	m.reportCount(count)
	slog.Info("detached per-cluster watcher", "cluster", cw.clusterName)
	if m.OnPurge != nil {
		m.OnPurge(m.parentCtx, cw.clusterName)
	}
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, cw := range m.active {
		cw.cancel()
		delete(m.active, key)
	}
	m.reportCount(0)
}

func (m *Manager) reportCount(n int) {
	if m.OnWatchedCount != nil {
		m.OnWatchedCount(n)
	}
}

// ActiveCount returns the number of active per-cluster watchers (for tests).
func (m *Manager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

// secretOf unwraps an informer object into a *corev1.Secret, handling tombstones.
func secretOf(obj any) *corev1.Secret {
	switch v := obj.(type) {
	case *corev1.Secret:
		return v
	case cache.DeletedFinalStateUnknown:
		if s, ok := v.Obj.(*corev1.Secret); ok {
			return s
		}
	}
	return nil
}
