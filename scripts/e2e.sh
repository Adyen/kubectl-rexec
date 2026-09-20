#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CLUSTER_NAME="${REXEC_CLUSTER_NAME:-rexec-e2e}"
KIND_NODE_IMAGE="${REXEC_NODE_IMAGE:-kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f}"
REXEC_IMAGE="${REXEC_IMAGE:-kubectl-rexec:e2e}"
TEST_IMAGE="${REXEC_TEST_IMAGE:-busybox:1.36.1}"
NAMESPACE="${REXEC_NAMESPACE:-rexec-e2e}"
OTHER_NAMESPACE="${REXEC_OTHER_NAMESPACE:-rexec-e2e-other}"
POD="${REXEC_POD:-exec-target}"
UNANNOTATED_POD="${REXEC_UNANNOTATED_POD:-unannotated-target}"
KEEP_CLUSTER="${REXEC_KEEP_CLUSTER:-false}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
TMP_PLUGIN_DIR=""
KIND_CONFIG=""
TMP_MANIFEST=""
FIXTURE_MANIFEST=""
TMP_COPY_DIR=""

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
}

cleanup() {
  [[ -z "${TMP_PLUGIN_DIR}" ]] || rm -rf "${TMP_PLUGIN_DIR}"
  [[ -z "${KIND_CONFIG}" ]] || rm -f "${KIND_CONFIG}"
  [[ -z "${TMP_MANIFEST}" ]] || rm -f "${TMP_MANIFEST}" "${TMP_MANIFEST}.bak"
  [[ -z "${FIXTURE_MANIFEST}" ]] || rm -f "${FIXTURE_MANIFEST}"
  [[ -z "${TMP_COPY_DIR}" ]] || rm -rf "${TMP_COPY_DIR}"
  if [[ "${KEEP_CLUSTER}" != "true" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

echo "validating prerequisites..."
require_command docker
require_command kind
require_command kubectl
require_command go
require_command sed

echo "creating kind cluster..."
kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
kind_args=(
  --name "${CLUSTER_NAME}"
  --image "${KIND_NODE_IMAGE}"
  --wait 180s
)
if [[ "${KIND_NODE_IMAGE}" == kindest/node:v1.29.* ]]; then
  KIND_CONFIG="$(mktemp)"
  cat > "${KIND_CONFIG}" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
- |
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
      feature-gates: TranslateStreamCloseWebsocketRequests=true
EOF
  kind_args+=(--config "${KIND_CONFIG}")
fi
kind create cluster "${kind_args[@]}"
[[ -z "${KIND_CONFIG}" ]] || rm -f "${KIND_CONFIG}"

echo "building kubectl plugin..."
TMP_PLUGIN_DIR="$(mktemp -d)"
go build -o "${TMP_PLUGIN_DIR}/kubectl-rexec" "${REPO_ROOT}/main.go"
export PATH="${TMP_PLUGIN_DIR}:${PATH}"
kubectl rexec --help >/dev/null

echo "building and loading images..."
docker build -t "${REXEC_IMAGE}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
docker pull "${TEST_IMAGE}" >/dev/null
kind load docker-image --name "${CLUSTER_NAME}" "${REXEC_IMAGE}" "${TEST_IMAGE}"

echo "deploying rexec manifests..."
TMP_MANIFEST="$(mktemp)"
kubectl kustomize "${REPO_ROOT}/manifests" > "${TMP_MANIFEST}"
sed -i.bak \
  -e "s#ghcr.io/adyen/kubectl-rexec:latest#${REXEC_IMAGE}#g" \
  -e "s#Always#IfNotPresent#g" \
  "${TMP_MANIFEST}"
rm -f "${TMP_MANIFEST}.bak"
kubectl --context "${KUBE_CONTEXT}" apply -f "${TMP_MANIFEST}"
rm -f "${TMP_MANIFEST}"

echo "waiting for deployment and apiservice..."
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/rexec -n kube-system --timeout=180s
kubectl --context "${KUBE_CONTEXT}" wait --for=condition=Available apiservice/v1beta1.audit.adyen.internal --timeout=180s

echo "creating exec contract fixtures..."
FIXTURE_MANIFEST="$(mktemp)"
sed \
  -e "s#__NAMESPACE__#${NAMESPACE}#g" \
  -e "s#__OTHER_NAMESPACE__#${OTHER_NAMESPACE}#g" \
  -e "s#__POD__#${POD}#g" \
  -e "s#__UNANNOTATED_POD__#${UNANNOTATED_POD}#g" \
  -e "s#__TEST_IMAGE__#${TEST_IMAGE}#g" \
  "${REPO_ROOT}/tests/e2e/fixtures.yaml" > "${FIXTURE_MANIFEST}"
kubectl --context "${KUBE_CONTEXT}" apply -f "${FIXTURE_MANIFEST}"
rm -f "${FIXTURE_MANIFEST}"

echo "waiting for exec contract fixtures..."
kubectl --context "${KUBE_CONTEXT}" wait \
  --for=condition=Ready pod \
  -l app=rexec-e2e-running \
  -n "${NAMESPACE}" \
  --timeout=180s
kubectl --context "${KUBE_CONTEXT}" wait \
  --for=condition=Ready pod/namespace-target \
  -n "${OTHER_NAMESPACE}" \
  --timeout=180s
kubectl --context "${KUBE_CONTEXT}" rollout status \
  deployment/resource-target \
  -n "${NAMESPACE}" \
  --timeout=180s
kubectl --context "${KUBE_CONTEXT}" wait \
  --for=jsonpath='{.status.phase}'=Succeeded \
  pod/completed-target \
  -n "${NAMESPACE}" \
  --timeout=60s

echo "running exec contract suite..."
export REXEC_E2E_CONTEXT="${KUBE_CONTEXT}"
export REXEC_E2E_NAMESPACE="${NAMESPACE}"
export REXEC_E2E_OTHER_NAMESPACE="${OTHER_NAMESPACE}"
export REXEC_E2E_PLUGIN="${TMP_PLUGIN_DIR}/kubectl-rexec"
export REXEC_E2E_POD="${POD}"
export REXEC_E2E_UNANNOTATED_POD="${UNANNOTATED_POD}"
export REXEC_E2E_USER
REXEC_E2E_USER="$(kubectl --context "${KUBE_CONTEXT}" auth whoami -o jsonpath='{.status.userInfo.username}')"
(
  cd "${REPO_ROOT}"
  go test -tags=e2e -v -count=1 -timeout=10m ./tests/e2e
)

echo "checking rexec cp download..."
token="rexec-$(date +%s)-${RANDOM}"
remote_file="/tmp/rexec-cp-${token}"
kubectl rexec --context "${KUBE_CONTEXT}" exec "${POD}" -n "${NAMESPACE}" -c primary -- sh -c "printf '%s' '${token}' > '${remote_file}'"
TMP_COPY_DIR="$(mktemp -d)"
kubectl rexec --context "${KUBE_CONTEXT}" cp "${POD}:${remote_file}" "${TMP_COPY_DIR}/" -n "${NAMESPACE}" -c primary
if ! grep -q "${token}" "${TMP_COPY_DIR}/$(basename "${remote_file}")"; then
  echo "error: copied file does not contain expected token" >&2
  exit 1
fi

echo "checking rexec cp upload rejection..."
upload_file="${TMP_COPY_DIR}/upload-${token}"
printf '%s' "${token}" > "${upload_file}"
if upload_error="$(kubectl rexec --context "${KUBE_CONTEXT}" cp "${upload_file}" "${POD}:/tmp/upload-${token}" -n "${NAMESPACE}" 2>&1)"; then
  echo "error: upload to pod succeeded unexpectedly" >&2
  exit 1
fi
if ! grep -q "copying to pods is not supported" <<<"${upload_error}"; then
  echo "error: unexpected upload rejection message: ${upload_error}" >&2
  exit 1
fi
rm -rf "${TMP_COPY_DIR}"

echo "e2e contract checks passed"
