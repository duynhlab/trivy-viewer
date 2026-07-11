#!/usr/bin/env bash
# Install Trivy Operator on an edge cluster (idempotent).
set -euo pipefail

CHART_VERSION="${TRIVY_OPERATOR_CHART_VERSION:-0.33.2}"
VALUES_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/values-edge.yaml"
NAMESPACE="${TRIVY_OPERATOR_NAMESPACE:-trivy-system}"
# Explicit context so the operator never lands on the hub by accident
# (kind create cluster switches the current context around).
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-edge}"

helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update

helm upgrade --install trivy-operator aqua/trivy-operator \
  --kube-context "$KUBE_CONTEXT" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --version "$CHART_VERSION" \
  -f "$VALUES_FILE"

echo "Trivy Operator $CHART_VERSION installed in namespace $NAMESPACE (context $KUBE_CONTEXT)"
