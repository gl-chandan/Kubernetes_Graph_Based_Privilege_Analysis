#!/usr/bin/env bash
# Dump the access-control configuration of the cluster kubectl currently points at.
# Secrets are NOT collected (only RBAC objects, ServiceAccounts, Pods, Namespaces).
#   k3s:  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
set -euo pipefail
OUT="${1:-data/k3s_snapshot}"
mkdir -p "$OUT"
kubectl get serviceaccounts        -A -o json > "$OUT/serviceaccounts.json"
kubectl get roles                  -A -o json > "$OUT/roles.json"
kubectl get rolebindings           -A -o json > "$OUT/rolebindings.json"
kubectl get clusterroles              -o json > "$OUT/clusterroles.json"
kubectl get clusterrolebindings       -o json > "$OUT/clusterrolebindings.json"
kubectl get pods                   -A -o json > "$OUT/pods.json"
kubectl get namespaces                -o json > "$OUT/namespaces.json"   # PSA labels
echo "Snapshot written to $OUT"
# Optional manual check of a reported edge, e.g. is SA X really admin?
#   kubectl auth can-i '*' '*' --as=system:serviceaccount:kube-system:helm-traefik
