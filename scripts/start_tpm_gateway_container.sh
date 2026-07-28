#!/usr/bin/env bash
set -euo pipefail

# Run the TPM REST API and the HTTPS gateway inside the same TPM-aware
# container. The gateway terminates TLS with a TPM-backed key, then proxies
# requests to the plain HTTP app running on the Docker network.

API_PORT="${TPM_GATEWAY_API_PORT:-8000}"
HTTPS_PORT="${TPM_GATEWAY_HTTPS_PORT:-8443}"
UPSTREAM_BASE_URL="${UPSTREAM_BASE_URL:-http://app:8080}"
WORK_DIR="${TPM_GATEWAY_WORK_DIR:-/opt/shared}"

KEY_FILE="${KEY_FILE:-server-key.tss2}"
PUBLIC_KEY_FILE="${PUBLIC_KEY_FILE:-server-key.pub.pem}"
CERT_FILE="${CERT_FILE:-server.crt}"
KEY_TYPE="${KEY_TYPE:-rsa}"
KEY_SIZE="${KEY_SIZE:-2048}"
CERT_DAYS="${CERT_DAYS:-30}"
KEY_PASSWORD="${KEY_PASSWORD:-}"

cd "${WORK_DIR}"

echo "Starting TPM REST API on 0.0.0.0:${API_PORT}"
python3 /opt/tpm2_rest_api.py "${API_PORT}" &
api_pid=$!

cleanup() {
  kill "${api_pid}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Waiting for TPM REST API readiness..."
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null

gateway_cmd=(
  python3 /opt/simple_tss2_tls_server.py
  --host 0.0.0.0
  --port "${HTTPS_PORT}"
  --api-base "http://127.0.0.1:${API_PORT}"
  --tcti "${TPM2OPENSSL_TCTI:-${TSS2_TCTI:-swtpm:host=127.0.0.1,port=2321}}"
  --key "${WORK_DIR}/${KEY_FILE}"
  --public-key "${WORK_DIR}/${PUBLIC_KEY_FILE}"
  --cert "${WORK_DIR}/${CERT_FILE}"
  --remote-key "${KEY_FILE}"
  --remote-public-key "${PUBLIC_KEY_FILE}"
  --remote-cert "${CERT_FILE}"
  --key-type "${KEY_TYPE}"
  --key-size "${KEY_SIZE}"
  --days "${CERT_DAYS}"
  --upstream-base "${UPSTREAM_BASE_URL}"
)

if [ -n "${KEY_PASSWORD}" ]; then
  gateway_cmd+=(--password "${KEY_PASSWORD}")
fi

echo "Starting TPM HTTPS gateway on 0.0.0.0:${HTTPS_PORT}"
echo "Proxying to upstream ${UPSTREAM_BASE_URL}"
exec "${gateway_cmd[@]}"
