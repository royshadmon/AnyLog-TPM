#!/usr/bin/env bash
set -euo pipefail

# Build/start a local TPM API container, then generate a TPM-backed TSS2 TLS key
# and a localhost certificate. The TSS2 file is a key reference, not an exported
# PEM private key.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_NAME="${IMAGE_NAME:-tpm2-api}"
CONTAINER_NAME="${CONTAINER_NAME:-tpm2-https-example}"
API_PORT="${API_PORT:-8001}"
TPM_PORT="${TPM_PORT:-2321}"
TPM_PLATFORM_PORT="${TPM_PLATFORM_PORT:-2322}"
HTTPS_PORT="${HTTPS_PORT:-9443}"
HTTPS_CONTAINER_PORT="${HTTPS_CONTAINER_PORT:-${HTTPS_PORT}}"
SHARED_DIR="${SHARED_DIR:-${REPO_DIR}/multiple-instances/tpm_shared_dir1}"
TPM_STATE_DIR="${TPM_STATE_DIR:-${SHARED_DIR}/tpm_state}"

KEY_FILE="${KEY_FILE:-server-key.tss2}"
PUBLIC_KEY_FILE="${PUBLIC_KEY_FILE:-server-key.pub.pem}"
CERT_FILE="${CERT_FILE:-server.crt}"
KEY_TYPE="${KEY_TYPE:-rsa}"
KEY_SIZE="${KEY_SIZE:-2048}"
CERT_DAYS="${CERT_DAYS:-30}"
KEY_PASSWORD="${KEY_PASSWORD:-}"

mkdir -p "${SHARED_DIR}" "${TPM_STATE_DIR}"

echo "Host shared directory: ${SHARED_DIR}"
echo "Container shared directory: /opt/shared"

echo "Building ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" "${REPO_DIR}"

current_shared_mount() {
  docker inspect -f '{{range .Mounts}}{{if eq .Destination "/opt/shared"}}{{.Source}}{{end}}{{end}}' "${CONTAINER_NAME}" 2>/dev/null || true
}

port_in_use() {
  local port="$1"
  lsof -Pi ":${port}" -sTCP:LISTEN -t >/dev/null 2>&1
}

if docker ps -a --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"; then
  mounted_dir="$(current_shared_mount)"
  if [ "${mounted_dir}" != "${SHARED_DIR}" ]; then
    echo "Recreating ${CONTAINER_NAME} so /opt/shared mounts ${SHARED_DIR}."
    echo "Previous /opt/shared mount: ${mounted_dir:-<none>}"
    docker rm -f "${CONTAINER_NAME}" >/dev/null
  fi
fi

if ! docker ps -a --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"; then
  for port in "${API_PORT}" "${TPM_PORT}" "${TPM_PLATFORM_PORT}" "${HTTPS_PORT}"; do
    if port_in_use "${port}"; then
      echo "Cannot start ${CONTAINER_NAME}: host port ${port} is already in use."
      echo "Use the existing TPM API container, or choose free API_PORT, TPM_PORT, TPM_PLATFORM_PORT, and HTTPS_PORT values."
      exit 1
    fi
  done

  echo "Starting ${CONTAINER_NAME} with REST API, swtpm, and shared output..."
  docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${API_PORT}:8000" \
    -p "${TPM_PORT}:2321" \
    -p "${TPM_PLATFORM_PORT}:2322" \
    -p "${HTTPS_PORT}:${HTTPS_CONTAINER_PORT}" \
    -v "${SHARED_DIR}:/opt/shared" \
    -v "${TPM_STATE_DIR}:/tmp/tpm2-emulated" \
    -w /opt/shared \
    -e TSS2_TCTI="swtpm:host=127.0.0.1,port=2321" \
    -e TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321" \
    -e TPM2OPENSSL_TCTI="swtpm:host=127.0.0.1,port=2321" \
    "${IMAGE_NAME}" \
    python3 /opt/tpm2_rest_api.py
elif [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}")" != "true" ]; then
  echo "Starting existing ${CONTAINER_NAME}..."
  docker start "${CONTAINER_NAME}" >/dev/null
else
  echo "Using running ${CONTAINER_NAME}."
fi

echo "Waiting for TPM REST API on http://127.0.0.1:${API_PORT}/health..."
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null

echo "Generating TPM-backed key reference and certificate..."
setup_cmd=(
  python3 /opt/simple_tss2_tls_server.py
  --setup-only
  --force-generate
  --host 0.0.0.0
  --port "${HTTPS_CONTAINER_PORT}"
  --api-base http://127.0.0.1:8000
  --tcti swtpm:host=127.0.0.1,port=2321
  --key "/opt/shared/${KEY_FILE}"
  --public-key "/opt/shared/${PUBLIC_KEY_FILE}"
  --cert "/opt/shared/${CERT_FILE}"
  --remote-key "${KEY_FILE}"
  --remote-public-key "${PUBLIC_KEY_FILE}"
  --remote-cert "${CERT_FILE}"
  --key-type "${KEY_TYPE}"
  --key-size "${KEY_SIZE}"
  --days "${CERT_DAYS}"
)

if [ -n "${KEY_PASSWORD}" ]; then
  setup_cmd+=(--password "${KEY_PASSWORD}")
fi

docker exec -w /opt/shared "${CONTAINER_NAME}" "${setup_cmd[@]}"

echo
echo "Generated files:"
echo "  ${SHARED_DIR}/${KEY_FILE}"
echo "  ${SHARED_DIR}/${PUBLIC_KEY_FILE}"
echo "  ${SHARED_DIR}/${CERT_FILE}"
echo
echo "Start HTTPS with:"
echo "  ./scripts/run_tpm_https_server.sh"
