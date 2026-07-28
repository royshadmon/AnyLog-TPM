#!/bin/bash
# Generates docker-compose.instances.yaml with N TPM instance services
# Usage: ./generate-docker-compose.sh [NUM_INSTANCES]
# If NUM_INSTANCES not specified, uses value from .num_instances or defaults to 3

set -e

INSTANCES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=shared-data-root.sh
source "$INSTANCES_DIR/shared-data-root.sh"
load_shared_data_root
load_shared_dir_prefix
load_swtpm_expose_ports
ENABLE_TPM_GATEWAY="${ENABLE_TPM_GATEWAY:-0}"
TPM_GATEWAY_UPSTREAM_BASE_URL="${TPM_GATEWAY_UPSTREAM_BASE_URL:-}"
TPM_GATEWAY_UPSTREAM_BASE_URLS="${TPM_GATEWAY_UPSTREAM_BASE_URLS:-}"
TPM_GATEWAY_API_PORT="${TPM_GATEWAY_API_PORT:-8000}"
TPM_GATEWAY_HTTPS_PORT="${TPM_GATEWAY_HTTPS_PORT:-8443}"
HTTPS_HOST_PORT_BASE="${HTTPS_HOST_PORT_BASE:-8442}"
TPM_GATEWAY_HTTPS_HOST_PORTS="${TPM_GATEWAY_HTTPS_HOST_PORTS:-}"
cd "$INSTANCES_DIR"

NUM_INSTANCES=${1:-$(cat .num_instances 2>/dev/null || echo "3")}

# Validate
if ! [[ "$NUM_INSTANCES" =~ ^[0-9]+$ ]] || [ "$NUM_INSTANCES" -lt 1 ]; then
    echo "Error: NUM_INSTANCES must be a positive integer (got: $NUM_INSTANCES)" >&2
    exit 1
fi

OUTPUT_FILE="docker-compose.instances.yaml"

UPSTREAM_VALUES=()
HTTPS_PORT_VALUES=()

if [ -n "$TPM_GATEWAY_UPSTREAM_BASE_URLS" ]; then
    IFS=',' read -r -a UPSTREAM_VALUES <<< "$TPM_GATEWAY_UPSTREAM_BASE_URLS"
    if [ "${#UPSTREAM_VALUES[@]}" -ne "$NUM_INSTANCES" ]; then
        echo "Error: TPM_GATEWAY_UPSTREAM_BASE_URLS must contain exactly $NUM_INSTANCES value(s)." >&2
        exit 1
    fi
fi

if [ -n "$TPM_GATEWAY_HTTPS_HOST_PORTS" ]; then
    IFS=',' read -r -a HTTPS_PORT_VALUES <<< "$TPM_GATEWAY_HTTPS_HOST_PORTS"
    if [ "${#HTTPS_PORT_VALUES[@]}" -ne "$NUM_INSTANCES" ]; then
        echo "Error: TPM_GATEWAY_HTTPS_HOST_PORTS must contain exactly $NUM_INSTANCES value(s)." >&2
        exit 1
    fi
    for port in "${HTTPS_PORT_VALUES[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            echo "Error: HTTPS host ports must be numeric (got: $port)." >&2
            exit 1
        fi
    done
fi

echo "Generating $OUTPUT_FILE with $NUM_INSTANCES TPM instance(s)..."
echo "  Volume host paths under: $SHARED_DATA_ROOT"

# Write the header - build context is parent (project root) where Dockerfile lives
cat > "$OUTPUT_FILE" << 'EOF'
# Auto-generated TPM instance services - DO NOT EDIT
# Regenerate with: ./generate-docker-compose.sh <NUM_INSTANCES>
# Or run: ./setup-multiple-instances.sh <NUM_INSTANCES>

version: '3.8'

services:
EOF

# Generate each instance - use absolute host paths so data can live outside multiple-instances/
for i in $(seq 1 $NUM_INSTANCES); do
    API_PORT=$((8000 + i))
    if [ "${#HTTPS_PORT_VALUES[@]}" -gt 0 ]; then
        TLS_PORT="${HTTPS_PORT_VALUES[$((i - 1))]}"
    else
        TLS_PORT=$((HTTPS_HOST_PORT_BASE + i))
    fi
    SWTPM_SERVER=$((2321 + (i - 1) * 2))
    SWTPM_CTRL=$((2322 + (i - 1) * 2))
    VOL_OPT="${SHARED_DATA_ROOT}/${SHARED_DIR_PREFIX}${i}"
    VOL_TPM="${SHARED_DATA_ROOT}/${SHARED_DIR_PREFIX}${i}/tpm_state"
    EXTRA_PORTS=""
    if [ "${SWTPM_EXPOSE_PORTS_RESOLVED:-false}" = "true" ]; then
        EXTRA_PORTS=$(cat <<EOF
      - "${SWTPM_SERVER}:${SWTPM_SERVER}"
      - "${SWTPM_CTRL}:${SWTPM_CTRL}"
EOF
)
    fi
    if [ "$ENABLE_TPM_GATEWAY" = "1" ]; then
        CONTAINER_COMMAND='sh -c "chmod 777 /opt/shared 2>/dev/null || true && mkdir -p /tmp/tpm2-emulated /opt/shared/key_backups && chmod 700 /tmp/tpm2-emulated 2>/dev/null || true && chmod 777 /opt/shared/key_backups 2>/dev/null || true && [ ! -f /opt/shared/signing_keys_metadata.json ] && echo '\''{}'\'' > /opt/shared/signing_keys_metadata.json || true && cd /opt/shared && /opt/start_tpm_gateway_container.sh"'
        GATEWAY_ENV=$(cat <<EOF
      - TPM_GATEWAY_API_PORT=${TPM_GATEWAY_API_PORT}
      - TPM_GATEWAY_HTTPS_PORT=${TPM_GATEWAY_HTTPS_PORT}
EOF
)
        if [ "${#UPSTREAM_VALUES[@]}" -gt 0 ]; then
            GATEWAY_ENV="${GATEWAY_ENV}
      - UPSTREAM_BASE_URL=${UPSTREAM_VALUES[$((i - 1))]}"
        elif [ -n "$TPM_GATEWAY_UPSTREAM_BASE_URL" ]; then
            GATEWAY_ENV="${GATEWAY_ENV}
      - UPSTREAM_BASE_URL=${TPM_GATEWAY_UPSTREAM_BASE_URL}"
        fi
    else
        CONTAINER_COMMAND='sh -c "chmod 777 /opt/shared 2>/dev/null || true && mkdir -p /tmp/tpm2-emulated /opt/shared/key_backups && chmod 700 /tmp/tpm2-emulated 2>/dev/null || true && chmod 777 /opt/shared/key_backups 2>/dev/null || true && [ ! -f /opt/shared/signing_keys_metadata.json ] && echo '\''{}'\'' > /opt/shared/signing_keys_metadata.json || true && cd /opt/shared && python3 /opt/tpm2_rest_api.py"'
        GATEWAY_ENV=""
    fi
    cat >> "$OUTPUT_FILE" << EOF

  tpm2-api-node${i}:
    build:
      context: ..
      dockerfile: Dockerfile
    container_name: tpm2-api-node${i}
    ports:
      - "${API_PORT}:8000"
      - "${TLS_PORT}:8443"
${EXTRA_PORTS}
    volumes:
      - "${VOL_OPT}:/opt/shared"
      - "${VOL_TPM}:/tmp/tpm2-emulated"
    working_dir: /opt/shared
    command: ${CONTAINER_COMMAND}
    user: root
    environment:
      - TSS2_TCTI=swtpm:host=127.0.0.1,port=${SWTPM_SERVER}
      - TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=${SWTPM_SERVER}
      - TPM2OPENSSL_TCTI=swtpm:host=127.0.0.1,port=${SWTPM_SERVER}
      - TPM2_TLS_API_BASE=http://127.0.0.1:8000
      - SWTPM_SERVER_PORT=${SWTPM_SERVER}
      - SWTPM_CTRL_PORT=${SWTPM_CTRL}
      - TPM_STATE_DIR=/tmp/tpm2-emulated
      - SWTPM_LOG_FILE=/var/log/swtpm-node${i}.log
${GATEWAY_ENV}
    restart: unless-stopped
EOF
done

# Persist the count for future runs
echo "$NUM_INSTANCES" > .num_instances

echo "✓ Generated $OUTPUT_FILE with $NUM_INSTANCES instance(s)"
echo "  API ports: 8001-$((8000 + NUM_INSTANCES))"
echo "  HTTPS test ports: $((HTTPS_HOST_PORT_BASE + 1))-$((HTTPS_HOST_PORT_BASE + NUM_INSTANCES))"
if [ "$ENABLE_TPM_GATEWAY" = "1" ]; then
    echo "  TPM HTTPS gateway mode: enabled"
    if [ -n "$TPM_GATEWAY_UPSTREAM_BASE_URLS" ]; then
        echo "    Upstream apps: $TPM_GATEWAY_UPSTREAM_BASE_URLS"
    elif [ -n "$TPM_GATEWAY_UPSTREAM_BASE_URL" ]; then
        echo "    Upstream app: $TPM_GATEWAY_UPSTREAM_BASE_URL"
    fi
    if [ -n "$TPM_GATEWAY_HTTPS_HOST_PORTS" ]; then
        echo "    HTTPS host ports: $TPM_GATEWAY_HTTPS_HOST_PORTS"
    fi
else
    echo "  TPM HTTPS gateway mode: disabled"
fi
if [ "${SWTPM_EXPOSE_PORTS_RESOLVED:-false}" = "true" ]; then
    echo "  SWTPM ports exposed: yes"
    echo "    Node 1 -> server 2321, control 2322"
    if [ "$NUM_INSTANCES" -gt 1 ]; then
        echo "    Node $NUM_INSTANCES -> server $((2321 + (NUM_INSTANCES - 1) * 2)), control $((2322 + (NUM_INSTANCES - 1) * 2))"
    fi
else
    echo "  SWTPM ports exposed: no"
fi
echo "  Start with: docker-compose -f multiple-instances/docker-compose.instances.yaml up -d"
