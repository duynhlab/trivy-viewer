package hub

import (
	"encoding/base64"
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// BuildRESTConfig builds a rest.Config from a ClusterConfig. The CA is
// base64-decoded; an empty CA with Insecure=false will fail TLS unless the
// server uses a publicly trusted cert.
func BuildRESTConfig(cfg ClusterConfig) (*rest.Config, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("cluster %q: empty server URL", cfg.Name)
	}
	restCfg := &rest.Config{
		Host:        cfg.Server,
		BearerToken: cfg.BearerToken,
	}
	restCfg.Insecure = cfg.Insecure
	if cfg.CAData != "" {
		ca, err := base64.StdEncoding.DecodeString(cfg.CAData)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: decode caData: %w", cfg.Name, err)
		}
		restCfg.CAData = ca
	}
	return restCfg, nil
}

// BuildDynamicClient builds a dynamic client for the given cluster config.
func BuildDynamicClient(cfg ClusterConfig) (dynamic.Interface, error) {
	restCfg, err := BuildRESTConfig(cfg)
	if err != nil {
		return nil, err
	}
	client, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster %q: build dynamic client: %w", cfg.Name, err)
	}
	return client, nil
}
