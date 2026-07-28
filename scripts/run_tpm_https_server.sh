#!/usr/bin/env bash
set -euo pipefail

PASSTHROUGH_ARGS=()
DOCKER_EXEC_TTY_ARGS=()

# Start the HTTPS example using an existing TPM REST API container by default.
#
# Host calls use TPM_API_BASE, normally http://127.0.0.1:8001 for the
# multiple-instances setup. Commands executed inside the TPM container use
# CONTAINER_TPM_API_BASE, normally http://127.0.0.1:8000 because the REST API is
# listening inside that same container.
#
# Missing TLS material is generated unless --no-generate is explicitly passed.
# The generated private-key file is a TPM-backed TSS2 reference, not an exported
# PEM private key.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SHARED_DIR="${SHARED_DIR:-${REPO_DIR}/multiple-instances/tpm_shared_dir1}"
CONTAINER_SHARED_DIR="${CONTAINER_SHARED_DIR:-/opt/shared}"

TPM_API_BASE="${TPM_API_BASE:-http://127.0.0.1:8001}"
CONTAINER_TPM_API_BASE="${CONTAINER_TPM_API_BASE:-http://127.0.0.1:8000}"
TPM_API_HOST="${TPM_API_HOST:-127.0.0.1}"
TPM_API_PORT="${TPM_API_PORT:-8001}"

TPM_API_CONTAINER="${TPM_API_CONTAINER:-}"
# Accept both the multi-instance naming scheme and the standalone demo name.
TPM_API_CONTAINER_CANDIDATES="${TPM_API_CONTAINER_CANDIDATES:-multiple-instances-tpm2-api-node1 tpm2-api-node1 tpm2-https-example}"

KEY_FILE="${KEY_FILE:-server-key.tss2}"
PUBLIC_KEY_FILE="${PUBLIC_KEY_FILE:-server-key.pub.pem}"
CERT_FILE="${CERT_FILE:-server.crt}"
KEY_TYPE="${KEY_TYPE:-rsa}"
KEY_SIZE="${KEY_SIZE:-2048}"
CERT_DAYS="${CERT_DAYS:-30}"
KEY_PASSWORD="${KEY_PASSWORD:-}"
HTTPS_PORT="${HTTPS_PORT:-8443}"

# Only start a new TPM stack when the caller explicitly opts in. The default
# avoids duplicate port binds when a multiple-instances TPM is already running.
START_TPM_CONTAINER="${START_TPM_CONTAINER:-0}"
TPM_COMMAND_PORT="${TPM_COMMAND_PORT:-2321}"
TPM_PLATFORM_PORT="${TPM_PLATFORM_PORT:-2322}"
REST_API_PORT="${REST_API_PORT:-}"

NO_GENERATE=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-generate)
      NO_GENERATE=1
      shift
      ;;
    --tpm-ip)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --tpm-ip"
        exit 1
      fi
      TPM_API_HOST="$2"
      shift 2
      ;;
    --port)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --port"
        exit 1
      fi
      TPM_API_PORT="$2"
      shift 2
      ;;
    --container-api-base)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --container-api-base"
        exit 1
      fi
      CONTAINER_TPM_API_BASE="$2"
      shift 2
      ;;
    --upstream-base)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --upstream-base"
        exit 1
      fi
      PASSTHROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    --help|-h)
      cat <<'EOF'
Usage: ./scripts/run_tpm_https_server.sh [options]

Options:
  --tpm-ip <host>              Host/IP where the TPM REST API is reachable from your shell
  --port <port>                Host port for the TPM REST API
  --no-generate                Require existing server-key.tss2 and server.crt
  --container-api-base <url>   API base URL used from inside the TPM container
  --upstream-base <url>        Optional HTTP upstream to proxy to from the TPM HTTPS gateway

Example:
  ./scripts/run_tpm_https_server.sh --tpm-ip 192.168.0.138 --port 8001 --upstream-base http://app:8080
EOF
      exit 0
      ;;
    *)
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

TPM_API_BASE="http://${TPM_API_HOST}:${TPM_API_PORT}"
if [ -z "${REST_API_PORT}" ]; then
  REST_API_PORT="${TPM_API_PORT}"
fi

if [ -t 0 ] && [ -t 1 ]; then
  DOCKER_EXEC_TTY_ARGS=(-it)
fi

key_path="${CONTAINER_SHARED_DIR}/${KEY_FILE}"
public_key_path="${CONTAINER_SHARED_DIR}/${PUBLIC_KEY_FILE}"
cert_path="${CONTAINER_SHARED_DIR}/${CERT_FILE}"

port_in_use() {
  local port="$1"
  lsof -Pi ":${port}" -sTCP:LISTEN -t >/dev/null 2>&1
}

container_running() {
  local container="$1"
  [ -n "${container}" ] && docker ps --format '{{.Names}}' | grep -Fxq "${container}"
}

container_exists() {
  local container="$1"
  [ -n "${container}" ] && docker ps -a --format '{{.Names}}' | grep -Fxq "${container}"
}

detect_tpm_container() {
  if [ -n "${TPM_API_CONTAINER}" ]; then
    echo "${TPM_API_CONTAINER}"
    return
  fi

  for candidate in ${TPM_API_CONTAINER_CANDIDATES}; do
    if container_exists "${candidate}"; then
      echo "${candidate}"
      return
    fi
  done

  # If the name-based lookup misses, reuse any container that publishes the
  # requested REST API host port and mounts the expected shared directory.
  while IFS= read -r container; do
    [ -n "${container}" ] || continue

    if ! docker inspect -f "{{with index .HostConfig.PortBindings \"8000/tcp\"}}{{(index . 0).HostPort}}{{end}}" "${container}" 2>/dev/null | grep -Fxq "${REST_API_PORT}"; then
      continue
    fi

    if [ "$(current_shared_mount "${container}")" = "${SHARED_DIR}" ]; then
      echo "${container}"
      return
    fi
  done < <(docker ps -a --format '{{.Names}}')
}

current_shared_mount() {
  local container="$1"
  docker inspect -f '{{range .Mounts}}{{if eq .Destination "/opt/shared"}}{{.Source}}{{end}}{{end}}' "${container}" 2>/dev/null || true
}

print_diagnostic() {
  local reason="$1"
  local container="${2:-}"
  echo
  echo "TPM API readiness failed: ${reason}"
  echo "TPM API base URL: ${TPM_API_BASE}"
  echo "TPM API container: ${container:-<not detected>}"
  if [ -n "${container}" ]; then
    if container_running "${container}"; then
      echo "Container running: yes"
    elif container_exists "${container}"; then
      echo "Container running: no"
    else
      echo "Container running: container not found"
    fi
    echo "Shared directory mounted at /opt/shared: $(current_shared_mount "${container}")"
    echo "Inspect logs with: docker logs --tail 100 ${container}"
  fi
  echo "Host shared directory expected: ${SHARED_DIR}"
  echo "Container shared directory expected: ${CONTAINER_SHARED_DIR}"
}

wait_for_tpm_api_ready() {
  local container="$1"
  local response=""
  local body=""
  local status=""
  local last_response=""

  echo "Checking TPM API readiness at ${TPM_API_BASE}/health ..."
  for attempt in $(seq 1 60); do
    response="$(curl -sS -w '\n%{http_code}' "${TPM_API_BASE}/health" 2>&1 || true)"
    status="$(printf '%s\n' "${response}" | tail -n 1)"
    body="$(printf '%s\n' "${response}" | sed '$d')"
    last_response="HTTP ${status}: ${body}"

    if [ "${status}" = "200" ] && printf '%s' "${body}" | grep -q '"status"[[:space:]]*:[[:space:]]*"healthy"'; then
      echo "TPM API ready after ${attempt} attempt(s)."
      return 0
    fi

    if [ "${status}" = "503" ] && printf '%s' "${body}" | grep -q 'TPM2 API not available'; then
      echo "Attempt ${attempt}: TPM REST API is up but not connected to TPM yet."
    else
      echo "Attempt ${attempt}: TPM API not ready yet (${last_response})."
    fi
    sleep 1
  done

  print_diagnostic "${last_response:-no response from /health}" "${container}"
  return 1
}

ensure_tpm_container() {
  local container
  container="$(detect_tpm_container)"

  if [ -n "${container}" ]; then
    TPM_API_CONTAINER="${container}"
    if container_running "${TPM_API_CONTAINER}"; then
      echo "Reusing existing TPM API container: ${TPM_API_CONTAINER}"
    else
      echo "Starting existing TPM API container: ${TPM_API_CONTAINER}"
      docker start "${TPM_API_CONTAINER}" >/dev/null
    fi
    return
  fi

  if [ "${START_TPM_CONTAINER}" != "1" ]; then
    print_diagnostic "no TPM API container was found and START_TPM_CONTAINER is not set to 1" ""
    exit 1
  fi

  for port in "${TPM_COMMAND_PORT}" "${TPM_PLATFORM_PORT}" "${REST_API_PORT}" "${HTTPS_PORT}"; do
    if port_in_use "${port}"; then
      echo "Cannot start a new TPM container because host port ${port} is already in use."
      echo "Use the running TPM API instead, or choose a free port with TPM_COMMAND_PORT, TPM_PLATFORM_PORT, REST_API_PORT, and HTTPS_PORT."
      exit 1
    fi
  done

  echo "No existing TPM API container found; START_TPM_CONTAINER=1 so starting one."
  API_PORT="${REST_API_PORT}" TPM_PORT="${TPM_COMMAND_PORT}" TPM_PLATFORM_PORT="${TPM_PLATFORM_PORT}" \
    HTTPS_PORT="${HTTPS_PORT}" HTTPS_CONTAINER_PORT="${HTTPS_PORT}" SHARED_DIR="${SHARED_DIR}" \
    "${SCRIPT_DIR}/setup_tpm_https_example.sh"
  TPM_API_CONTAINER="$(detect_tpm_container)"
  if [ -z "${TPM_API_CONTAINER}" ]; then
    TPM_API_CONTAINER="${CONTAINER_NAME:-tpm2-https-example}"
  fi
}

mkdir -p "${SHARED_DIR}"

echo "TPM API base URL from host: ${TPM_API_BASE}"
echo "TPM API base URL inside container: ${CONTAINER_TPM_API_BASE}"
echo "Host shared directory: ${SHARED_DIR}"
echo "Container shared directory: ${CONTAINER_SHARED_DIR}"

ensure_tpm_container

mounted_dir="$(current_shared_mount "${TPM_API_CONTAINER}")"
if [ "${mounted_dir}" != "${SHARED_DIR}" ]; then
  print_diagnostic "container /opt/shared mount does not match the expected host shared directory" "${TPM_API_CONTAINER}"
  exit 1
fi

wait_for_tpm_api_ready "${TPM_API_CONTAINER}"

key_exists=0
cert_exists=0
if docker exec "${TPM_API_CONTAINER}" test -f "${key_path}"; then
  key_exists=1
fi
if docker exec "${TPM_API_CONTAINER}" test -f "${cert_path}"; then
  cert_exists=1
fi

if [ "${NO_GENERATE}" -eq 1 ]; then
  echo "Strict startup requested with --no-generate; existing TPM TLS material is required."
  if [ "${key_exists}" -eq 0 ] || [ "${cert_exists}" -eq 0 ]; then
    echo "Refusing to generate TPM TLS material because --no-generate was explicitly requested."
    if [ "${key_exists}" -eq 0 ]; then
      echo "  missing key:  ${key_path}"
    fi
    if [ "${cert_exists}" -eq 0 ]; then
      echo "  missing cert: ${cert_path}"
    fi
    exit 1
  fi
elif [ "${key_exists}" -eq 1 ] && [ "${cert_exists}" -eq 1 ]; then
  echo "Reusing existing TPM TLS material:"
  echo "  ${key_path}"
  echo "  ${cert_path}"
else
  echo "Generating missing TPM TLS material before starting HTTPS:"
  if [ "${key_exists}" -eq 0 ]; then
    echo "  missing key:  ${key_path}"
  fi
  if [ "${cert_exists}" -eq 0 ]; then
    echo "  missing cert: ${cert_path}"
  fi
  echo "The private key will be stored as a TPM-backed TSS2 reference, not a normal PEM private key."
fi

server_cmd=(
  python3 /opt/simple_tss2_tls_server.py
  --host 0.0.0.0
  --port "${HTTPS_PORT}"
  --api-base "${CONTAINER_TPM_API_BASE}"
  --tcti swtpm:host=127.0.0.1,port=2321
  --key "${key_path}"
  --public-key "${public_key_path}"
  --cert "${cert_path}"
  --remote-key "${KEY_FILE}"
  --remote-public-key "${PUBLIC_KEY_FILE}"
  --remote-cert "${CERT_FILE}"
  --key-type "${KEY_TYPE}"
  --key-size "${KEY_SIZE}"
  --days "${CERT_DAYS}"
)

if [ "${NO_GENERATE}" -eq 1 ]; then
  server_cmd+=(--no-generate)
fi

if [ -n "${KEY_PASSWORD}" ]; then
  server_cmd+=(--password "${KEY_PASSWORD}")
fi

if [ "${#PASSTHROUGH_ARGS[@]}" -gt 0 ]; then
  server_cmd+=("${PASSTHROUGH_ARGS[@]}")
fi

echo "Starting HTTPS server inside ${TPM_API_CONTAINER} on container port ${HTTPS_PORT}."
echo "Expected host URL: https://127.0.0.1:${HTTPS_PORT}"
docker_exec_cmd=(docker exec)
if [ "${#DOCKER_EXEC_TTY_ARGS[@]}" -gt 0 ]; then
  docker_exec_cmd+=("${DOCKER_EXEC_TTY_ARGS[@]}")
fi
docker_exec_cmd+=(-w "${CONTAINER_SHARED_DIR}" "${TPM_API_CONTAINER}")
docker_exec_cmd+=("${server_cmd[@]}")
"${docker_exec_cmd[@]}"
