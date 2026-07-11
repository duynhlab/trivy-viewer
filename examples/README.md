# Local Kind example — step by step

End-to-end walkthrough: hub + one edge cluster, Trivy Operator, reader RBAC, and trivy-viewer Helm. Run commands from the **repository root**.

Architecture, Admin UI registration wizard, and diagrams: [root README](../README.md).

## Prerequisites

- Docker (running)
- [kind](https://kind.sigs.k8s.io/)
- `kubectl`, `helm` 3.x

## 1. Create clusters

```bash
kind create cluster --name hub --config examples/kind/cluster-hub.yaml
kind create cluster --name edge --config examples/kind/cluster-edge.yaml
```

> **Note:** `kind create cluster` switches your current kubectl context to the
> cluster it just created — after these two commands you are on `kind-edge`.
> Every command below therefore passes an explicit context.

The edge config exposes the API on host port `127.0.0.1:6444` — that is for
`kubectl` **from your workstation** only. The hub scraper pod cannot reach
your host loopback; it connects to the edge node's Docker-network IP instead
(step 5).

## 2. Hub — CRDs and trivy-viewer

Installs the released chart from GHCR (image `ghcr.io/duynhlab/trivy-viewer`
comes from the chart's `appVersion` — no local build needed):

```bash
kubectl --context kind-hub apply -f examples/kind/trivy-crds.yaml

helm install trivy-viewer oci://ghcr.io/duynhlab/charts/trivy-viewer \
  --kube-context kind-hub \
  --namespace trivy-system --create-namespace
```

In a **second terminal** (port-forward blocks):

```bash
kubectl --context kind-hub -n trivy-system port-forward svc/trivy-viewer-server 3000:3000
```

Open http://localhost:3000

> Installing from a checkout instead? Replace the chart reference with the
> local path: `helm install trivy-viewer charts/trivy-viewer --kube-context kind-hub ...`

## 3. Edge — Trivy Operator

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update

helm upgrade --install trivy-operator aqua/trivy-operator \
  --kube-context kind-edge \
  --namespace trivy-system --create-namespace \
  --version 0.33.2 \
  -f examples/trivy-operator/values-edge.yaml
```

Or use the helper script:

```bash
bash examples/trivy-operator/install-edge.sh
```

Chart version is pinned in `install-edge.sh` (override with `TRIVY_OPERATOR_CHART_VERSION`). Official docs: https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/helm/

### Optional — scan the hub cluster too

By default only registered edges show data. To also see the hub's own
workloads (they appear as cluster **`local`** — the chart's
`scraper.clusterName`), install the operator on the hub as well.

The operator ships the full report CRDs and refuses to overwrite the minimal
ones applied in step 2, so replace them first:

```bash
kubectl --context kind-hub delete crd \
  vulnerabilityreports.aquasecurity.github.io \
  sbomreports.aquasecurity.github.io

KUBE_CONTEXT=kind-hub bash examples/trivy-operator/install-edge.sh

# The local watcher lost its CRD watch when the CRDs were deleted — restart:
kubectl --context kind-hub -n trivy-system rollout restart deploy/trivy-viewer-scraper

kubectl --context kind-hub apply -f examples/kind/demo-workload.yaml
```

The scraper's local watcher (`scraper.watchLocal`, on by default) picks the
reports up as the operator creates them — no registration needed. Stored
reports are unaffected (they live in SQLite, not in the CRDs).

## 4. Edge — reader RBAC and demo workload

```bash
kubectl --context kind-edge apply -f examples/kind/edge-reader-rbac.yaml
kubectl --context kind-edge apply -f examples/kind/demo-workload.yaml
```

Wait 1–5 minutes for the operator to create `VulnerabilityReport` CRs:

```bash
kubectl --context kind-edge get vulnerabilityreports -A
```

## 5. Register the edge on the hub

Extract the credentials. For Kind, the API server URL the **hub scraper**
uses is the edge node's Docker-network IP — not `127.0.0.1:6444`:

```bash
EDGE_IP=$(docker inspect edge-control-plane \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
SERVER="https://$EDGE_IP:6443"

TOKEN=$(kubectl --context kind-edge -n trivy-system \
  get secret trivy-viewer-reader-token -o jsonpath='{.data.token}' | base64 -d)
CA=$(kubectl --context kind-edge -n trivy-system \
  get secret trivy-viewer-reader-token -o jsonpath='{.data.ca\.crt}')

echo "server: $SERVER"
```

Then register in **Admin → Clusters** (`/admin/clusters`) with `SERVER`,
`CA`, and `TOKEN` — leave **Skip TLS verify** off; the Kind API certificate
includes the node IP, so the CA verifies. Full wizard walkthrough:
**[Register edge clusters via Admin UI](../README.md#register-edge-clusters-via-admin-ui)**.

Or register via API:

```bash
curl -sS -X POST http://localhost:3000/api/v1/hub/clusters \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"edge-1\",\"server\":\"$SERVER\",\"ca_data\":\"$CA\",\"bearer_token\":\"$TOKEN\"}"
```

## 6. Verify

- **Admin → Clusters** — edge shows **Synced** after reports are in the DB.
- **Dashboard** / **Vulnerabilities** — data from the edge.

## File layout

```
examples/
  README.md                 # this file
  kind/
    cluster-hub.yaml
    cluster-edge.yaml       # apiServerPort: 6444
    trivy-crds.yaml
    edge-reader-rbac.yaml
    demo-workload.yaml
  trivy-operator/
    values-edge.yaml
    install-edge.sh
```

| File | Purpose |
|------|---------|
| `kind/cluster-hub.yaml` | Kind config for hub |
| `kind/cluster-edge.yaml` | Kind config for edge (API port 6444) |
| `kind/trivy-crds.yaml` | Trivy Operator CRDs (hub + edge, before operator/viewer) |
| `kind/edge-reader-rbac.yaml` | Read-only SA for hub-pull |
| `kind/demo-workload.yaml` | nginx Deployment to trigger scans |
| `trivy-operator/values-edge.yaml` | Helm values: vuln + SBOM reports, Kind-friendly resources |
| `trivy-operator/install-edge.sh` | Idempotent operator install (chart 0.33.2) |

## Hub vs edge operator

| Hub mode | Edge | Hub |
|----------|------|-----|
| Hub-pull only (default) | operator + reader RBAC | CRDs + trivy-viewer Helm only |
| Hub + local scans | operator on edges | operator on hub **or** CRDs + `watchLocal` |

## Second edge cluster

Copy `kind/cluster-edge.yaml` with `apiServerPort: 6445`, then
`kind create cluster --name edge-2 --config <copy>.yaml` (the `--name` flag
overrides the config's `name:` field). Repeat steps 3–5 with the new
context `kind-edge-2` and node `edge-2-control-plane`.
