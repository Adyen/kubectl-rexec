#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CLUSTER_NAME="${REXEC_CLUSTER_NAME:-rexec-e2e}"
KIND_NODE_IMAGE="${REXEC_NODE_IMAGE:-kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f}"
REXEC_IMAGE="${REXEC_IMAGE:-kubectl-rexec:e2e}"
TEST_IMAGE="${REXEC_TEST_IMAGE:-busybox:1.36.1}"
NAMESPACE="${REXEC_NAMESPACE:-default}"
POD="${REXEC_POD:-test-pod}"
KEEP_CLUSTER="${REXEC_KEEP_CLUSTER:-false}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
TMP_PLUGIN_DIR=""

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
}

cleanup() {
  if [[ -n "${TMP_PLUGIN_DIR}" ]] && [[ -d "${TMP_PLUGIN_DIR}" ]]; then
    rm -rf "${TMP_PLUGIN_DIR}"
  fi
  if [[ "${KEEP_CLUSTER}" != "true" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

wait_for_log_token() {
  local token="$1"
  for _ in $(seq 1 20); do
    if kubectl --context "${KUBE_CONTEXT}" logs -n kube-system -l app=rexec --since=2m 2>&1 | grep -q "${token}"; then
      return 0
    fi
    sleep 1
  done
  echo "error: token '${token}' not found in rexec logs" >&2
  exit 1
}

echo "validating prerequisites..."
require_command docker
require_command kind
require_command kubectl
require_command go
require_command sed

echo "creating kind cluster..."
kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
kind create cluster --name "${CLUSTER_NAME}" --image "${KIND_NODE_IMAGE}" --wait 180s

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
tmp_manifest="$(mktemp)"
kubectl kustomize "${REPO_ROOT}/manifests" > "${tmp_manifest}"
sed -i.bak \
  -e "s#ghcr.io/adyen/kubectl-rexec:latest#${REXEC_IMAGE}#g" \
  -e "s#Always#IfNotPresent#g" \
  "${tmp_manifest}"
rm -f "${tmp_manifest}.bak"
kubectl --context "${KUBE_CONTEXT}" apply -f "${tmp_manifest}"
rm -f "${tmp_manifest}"

echo "waiting for deployment and apiservice..."
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/rexec -n kube-system --timeout=180s
kubectl --context "${KUBE_CONTEXT}" wait --for=condition=Available apiservice/v1beta1.audit.adyen.internal --timeout=180s

echo "creating test pod..."
if ! kubectl --context "${KUBE_CONTEXT}" get pod "${POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  kubectl --context "${KUBE_CONTEXT}" run "${POD}" -n "${NAMESPACE}" --restart=Never --image "${TEST_IMAGE}" -- sleep infinity
fi
kubectl --context "${KUBE_CONTEXT}" wait --for=condition=Ready "pod/${POD}" -n "${NAMESPACE}" --timeout=180s

token="rexec-$(date +%s)-${RANDOM}"
echo "checking rexec exec..."
exec_output="$(kubectl rexec --context "${KUBE_CONTEXT}" exec "${POD}" -n "${NAMESPACE}" -- echo "${token}")"
if ! grep -q "${token}" <<<"${exec_output}"; then
  echo "error: expected token in rexec exec output" >&2
  exit 1
fi

echo "checking audit logs..."
wait_for_log_token "${token}"

echo "checking rexec cp download..."
remote_file="/tmp/rexec-cp-${token}"
kubectl rexec --context "${KUBE_CONTEXT}" exec "${POD}" -n "${NAMESPACE}" -- sh -c "printf '%s' '${token}' > '${remote_file}'"
tmp_dir="$(mktemp -d)"
kubectl rexec --context "${KUBE_CONTEXT}" cp "${POD}:${remote_file}" "${tmp_dir}/" -n "${NAMESPACE}"
if ! grep -q "${token}" "${tmp_dir}/$(basename "${remote_file}")"; then
  echo "error: copied file does not contain expected token" >&2
  rm -rf "${tmp_dir}"
  exit 1
fi

echo "checking rexec cp upload rejection..."
upload_file="${tmp_dir}/upload-${token}"
printf '%s' "${token}" > "${upload_file}"
if upload_error="$(kubectl rexec --context "${KUBE_CONTEXT}" cp "${upload_file}" "${POD}:/tmp/upload-${token}" -n "${NAMESPACE}" 2>&1)"; then
  echo "error: upload to pod succeeded unexpectedly" >&2
  rm -rf "${tmp_dir}"
  exit 1
fi
if ! grep -q "copying to pods is not supported" <<<"${upload_error}"; then
  echo "error: unexpected upload rejection message: ${upload_error}" >&2
  rm -rf "${tmp_dir}"
  exit 1
fi
rm -rf "${tmp_dir}"

echo "checking direct kubectl exec denial..."
if direct_exec_output="$(kubectl --context "${KUBE_CONTEXT}" exec "${POD}" -n "${NAMESPACE}" -- echo denied 2>&1)"; then
  echo "error: direct kubectl exec succeeded unexpectedly" >&2
  exit 1
fi
if ! grep -q "cannot use exec directly, use rexec plugin instead" <<<"${direct_exec_output}"; then
  echo "error: unexpected direct exec denial message: ${direct_exec_output}" >&2
  exit 1
fi

echo "e2e smoke checks passed"
