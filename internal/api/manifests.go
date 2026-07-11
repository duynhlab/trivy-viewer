package api

import "fmt"

// edgeRBACYAML returns the read-only RBAC to apply on an Edge cluster: a
// ServiceAccount, a strictly read-only ClusterRole scoped to Trivy CRDs, a
// binding, and a long-lived token Secret. Mirrors the upstream footprint.
func edgeRBACYAML(namespace string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: trivy-viewer-reader
  namespace: %[1]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trivy-viewer-reader
rules:
  - apiGroups: ["aquasecurity.github.io"]
    resources: ["vulnerabilityreports", "sbomreports"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: trivy-viewer-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: trivy-viewer-reader
subjects:
  - kind: ServiceAccount
    name: trivy-viewer-reader
    namespace: %[1]s
---
apiVersion: v1
kind: Secret
metadata:
  name: trivy-viewer-reader-token
  namespace: %[1]s
  annotations:
    kubernetes.io/service-account.name: trivy-viewer-reader
type: kubernetes.io/service-account-token
`, namespace)
}

// extractCommands returns a copy-paste bash block that prints the SA token, CA,
// and API server URL an operator pastes into the registration form.
func extractCommands(namespace string) string {
	return fmt.Sprintf(`# Run on the Edge cluster with an admin kubeconfig
SA_TOKEN=$(kubectl -n %[1]s get secret trivy-viewer-reader-token -o jsonpath='{.data.token}' | base64 -d)
CA_DATA=$(kubectl -n %[1]s get secret trivy-viewer-reader-token -o jsonpath='{.data.ca\.crt}')
API_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
# Kind/local only: the kubeconfig URL is your host loopback, which the hub
# cannot reach. Use the edge node IP instead, e.g.:
#   API_SERVER="https://$(docker inspect <edge>-control-plane --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'):6443"
echo "server:      $API_SERVER"
echo "bearerToken: $SA_TOKEN"
echo "caData:      $CA_DATA"
`, namespace)
}

// hubSecretTemplate returns a GitOps-friendly Secret manifest for registration
// without the UI.
func hubSecretTemplate(hubNamespace, clusterName string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: cluster-%[2]s
  namespace: %[1]s
  labels:
    trivy-viewer.io/secret-type: cluster
    app.kubernetes.io/managed-by: trivy-viewer
type: Opaque
stringData:
  name: %[2]s
  server: https://<edge-api-server>:443
  config: |
    {
      "bearerToken": "<decoded-SA-token>",
      "tlsClientConfig": { "caData": "<base64-CA>" }
    }
  namespaces: "[]"
`, hubNamespace, clusterName)
}
