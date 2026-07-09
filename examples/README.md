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

The edge API is exposed on `127.0.0.1:6444` so the hub scraper can reach it via the host (see [Kind networking](../README.md#kind-networking) in the root README).

## 2. Hub — CRDs and trivy-viewer

```bash
kubectl --context kind-hub apply -f examples/kind/trivy-crds.yaml

helm install trivy-viewer charts/trivy-viewer \
  --namespace trivy-system --create-namespace

kubectl --context kind-hub -n trivy-system port-forward svc/trivy-viewer-server 3000:3000
```

Open http://localhost:3000

## 3. Edge — Trivy Operator

```bash
kubectl config use-context kind-edge

helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update

helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system --create-namespace \
  --version 0.33.2 \
  -f examples/trivy-operator/values-edge.yaml
```

Or use the helper script:

```bash
bash examples/trivy-operator/install-edge.sh
```

Chart version is pinned in `install-edge.sh` (override with `TRIVY_OPERATOR_CHART_VERSION`). Official docs: https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/helm/

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

Follow **[Register edge clusters via Admin UI](../README.md#register-edge-clusters-via-admin-ui)** (`Admin → Clusters` wizard).

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

Copy `kind/cluster-edge.yaml` with `name: edge-2` and `apiServerPort: 6445`, create the cluster, repeat steps 3–5 with a new name in the Admin UI wizard.
