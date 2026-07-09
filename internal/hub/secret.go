package hub

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// secretConfig is the JSON shape of the Secret's `config` field (ArgoCD-compatible).
type secretConfig struct {
	BearerToken     string `json:"bearerToken"`
	TLSClientConfig struct {
		CAData   string `json:"caData"`
		Insecure bool   `json:"insecure"`
	} `json:"tlsClientConfig"`
}

// ParseClusterSecret converts a cluster Secret into a ClusterConfig. Fields are
// read from Secret.Data (already base64-decoded by the API machinery).
func ParseClusterSecret(s *corev1.Secret) (ClusterConfig, error) {
	get := func(k string) string { return string(s.Data[k]) }

	cfg := ClusterConfig{
		Name:   get("name"),
		Server: get("server"),
	}
	if cfg.Name == "" {
		return ClusterConfig{}, fmt.Errorf("cluster secret %s/%s: missing 'name'", s.Namespace, s.Name)
	}
	if cfg.Server == "" {
		return ClusterConfig{}, fmt.Errorf("cluster secret %s/%s: missing 'server'", s.Namespace, s.Name)
	}

	if raw := get("config"); raw != "" {
		var sc secretConfig
		if err := json.Unmarshal([]byte(raw), &sc); err != nil {
			return ClusterConfig{}, fmt.Errorf("cluster secret %s/%s: invalid config JSON: %w", s.Namespace, s.Name, err)
		}
		cfg.BearerToken = sc.BearerToken
		cfg.CAData = sc.TLSClientConfig.CAData
		cfg.Insecure = sc.TLSClientConfig.Insecure
	}

	if raw := get("namespaces"); raw != "" {
		var nss []string
		if err := json.Unmarshal([]byte(raw), &nss); err != nil {
			return ClusterConfig{}, fmt.Errorf("cluster secret %s/%s: invalid namespaces JSON: %w", s.Namespace, s.Name, err)
		}
		cfg.Namespaces = nss
	}
	return cfg, nil
}

// HasClusterLabel reports whether a Secret carries the cluster registration label.
func HasClusterLabel(s *corev1.Secret) bool {
	return s.Labels[SecretTypeLabelKey] == SecretTypeCluster
}
