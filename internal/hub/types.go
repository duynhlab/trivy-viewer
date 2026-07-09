// Package hub implements the ArgoCD-style cluster registration: reading cluster
// Secrets, building read-only clients for each Edge cluster, and managing the
// per-cluster watcher lifecycle. See docs/01-architecture.md and ADR-002.
package hub

// Label identifying a cluster-registration Secret in the Hub namespace.
const (
	SecretTypeLabelKey = "trivy-viewer.io/secret-type"
	SecretTypeCluster  = "cluster"
	ManagedByLabelKey  = "app.kubernetes.io/managed-by"
	ManagedByValue     = "trivy-viewer"
)

// ClusterConfig is the parsed form of a cluster Secret.
type ClusterConfig struct {
	Name        string   // logical cluster name (tag on reports)
	Server      string   // https://api:443
	BearerToken string   // Edge SA token
	CAData      string   // base64-encoded CA bundle
	Insecure    bool     // skip TLS verification (discouraged)
	Namespaces  []string // empty = all namespaces
}
