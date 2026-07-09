package hub

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/duynhlab/trivy-viewer/internal/watcher"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func clusterSecret(name, clusterName, rv string) *corev1.Secret {
	cfg := `{"bearerToken":"tok","tlsClientConfig":{"caData":"` +
		base64.StdEncoding.EncodeToString([]byte("ca")) + `"}}`
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       "trivy-system",
			ResourceVersion: rv,
			Labels:          map[string]string{SecretTypeLabelKey: SecretTypeCluster},
		},
		Data: map[string][]byte{
			"name":       []byte(clusterName),
			"server":     []byte("https://edge:443"),
			"config":     []byte(cfg),
			"namespaces": []byte("[]"),
		},
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func TestManagerSpawnsAndStopsWatchers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kube := fake.NewSimpleClientset(clusterSecret("cluster-edge-a", "edge-a", "1"))

	scheme := k8sruntime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		watcher.VulnGVR: "VulnerabilityReportList",
		watcher.SbomGVR: "SbomReportList",
	}
	fakeDyn := func(ClusterConfig) (dynamic.Interface, error) {
		return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds), nil
	}

	var mu sync.Mutex
	var purged []string
	mgr := NewManager(kube, "trivy-system", func(watcher.Event) {}, fakeDyn)
	mgr.OnPurge = func(_ context.Context, cluster string) {
		mu.Lock()
		defer mu.Unlock()
		purged = append(purged, cluster)
	}
	purgedContains := func(name string) bool {
		mu.Lock()
		defer mu.Unlock()
		return len(purged) == 1 && purged[0] == name
	}

	go func() { _ = mgr.Run(ctx) }()

	waitFor(t, func() bool { return mgr.ActiveCount() == 1 })

	// Delete the secret -> watcher should stop and purge fire.
	if err := kube.CoreV1().Secrets("trivy-system").Delete(ctx, "cluster-edge-a", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	waitFor(t, func() bool { return mgr.ActiveCount() == 0 })
	waitFor(t, func() bool { return purgedContains("edge-a") })
}
