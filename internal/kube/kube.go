// Package kube builds Kubernetes clients for the Hub's own cluster, working both
// in-cluster (pod ServiceAccount) and from a local kubeconfig for development.
package kube

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// RESTConfig returns the in-cluster config if available, otherwise falls back to
// the default kubeconfig loading rules (KUBECONFIG / ~/.kube/config).
func RESTConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return cfg, nil
}

// Clients builds the typed and dynamic clients for the local cluster.
func Clients() (kubernetes.Interface, dynamic.Interface, error) {
	cfg, err := RESTConfig()
	if err != nil {
		return nil, nil, err
	}
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build dynamic client: %w", err)
	}
	return typed, dyn, nil
}

// CurrentNamespace resolves the namespace to watch for cluster Secrets. It uses
// the explicit override if set, else the in-cluster ServiceAccount namespace,
// else "default".
func CurrentNamespace(override string) string {
	if override != "" {
		return override
	}
	if data, err := os.ReadFile(saNamespaceFile); err == nil {
		if ns := strings.TrimSpace(string(data)); ns != "" {
			return ns
		}
	}
	return "default"
}
