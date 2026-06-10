#!/bin/bash
# Helper script to set up directories for multiple TPM instances
# Usage: ./setup-multiple-instances.sh [OPTIONS] [NUM_INSTANCES]
# Options --name and --path update .instances-prefix and .instances-path (same as env / files elsewhere).
# Supports any number of instances (default: 3)
# Creates or deletes folders to match the requested count exactly.

set -e

INSTANCES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$INSTANCES_DIR")"

if command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    DOCKER_COMPOSE_CMD="docker-compose"
fi

show_setup_help() {
    cat << EOF
Usage: $0 [OPTIONS] [NUM_INSTANCES]

  NUM_INSTANCES   Number of TPM instances (default: value in .num_instances or 3)

Options:
  --name PREFIX   Set folder name prefix (writes .instances-prefix). Directories are PREFIX1, PREFIX2, ...
                  Must not contain '/'. Overrides SWTPM_SHARED_DIR_PREFIX for this run after write.
  --path PATH     Set parent directory for instance folders (writes .instances-path). Absolute path, or
                  relative to multiple-instances/. Overrides SWTPM_SHARED_DATA_ROOT for this run after write.
  -h, --help      Show this help

Examples:
  $0 5
  $0 --name tpm_shared_dir --path ../docs 3
  $0 --path /var/lib/swtpm-data 10
EOF
}

NUM_INSTANCES=""
CLI_NAME=""
CLI_PATH=""
while [ $# -gt 0 ]; do
    case "$1" in
        --name)
            [ -n "${2:-}" ] || { echo "Error: --name requires a value" >&2; exit 1; }
            CLI_NAME="$2"
            shift 2
            ;;
        --path)
            [ -n "${2:-}" ] || { echo "Error: --path requires a value" >&2; exit 1; }
            CLI_PATH="$2"
            shift 2
            ;;
        -h|--help)
            show_setup_help
            exit 0
            ;;
        -*)
            echo "Error: unknown option: $1" >&2
            show_setup_help >&2
            exit 1
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                if [ -n "$NUM_INSTANCES" ]; then
                    echo "Error: multiple NUM_INSTANCES values (got: $NUM_INSTANCES and $1)" >&2
                    exit 1
                fi
                NUM_INSTANCES="$1"
            else
                echo "Error: unexpected argument: $1" >&2
                show_setup_help >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -n "$CLI_NAME" ]; then
    if [[ "$CLI_NAME" == */* ]]; then
        echo "Error: --name must not contain '/' (got: $CLI_NAME)" >&2
        exit 1
    fi
    {
        echo "# Written by setup-multiple-instances.sh --name (instance dirs: ${CLI_NAME}1, ${CLI_NAME}2, ...)"
        echo "$CLI_NAME"
    } > "$INSTANCES_DIR/.instances-prefix"
    echo "Updated $INSTANCES_DIR/.instances-prefix -> $CLI_NAME"
    unset SWTPM_SHARED_DIR_PREFIX
fi

if [ -n "$CLI_PATH" ]; then
    {
        echo "# Written by setup-multiple-instances.sh --path (parent of PREFIX1, PREFIX2, ...)"
        echo "# Non-absolute paths are relative to multiple-instances/"
        echo "$CLI_PATH"
    } > "$INSTANCES_DIR/.instances-path"
    echo "Updated $INSTANCES_DIR/.instances-path -> $CLI_PATH"
    unset SWTPM_SHARED_DATA_ROOT
fi

# shellcheck source=shared-data-root.sh
source "$INSTANCES_DIR/shared-data-root.sh"
load_shared_data_root
load_shared_dir_prefix
cd "$INSTANCES_DIR"

NUM_INSTANCES=${NUM_INSTANCES:-$(cat .num_instances 2>/dev/null || echo "3")}

# Validate
if ! [[ "$NUM_INSTANCES" =~ ^[0-9]+$ ]] || [ "$NUM_INSTANCES" -lt 1 ]; then
    echo "Error: NUM_INSTANCES must be a positive integer (got: $NUM_INSTANCES)" >&2
    exit 1
fi

echo "Setting up exactly $NUM_INSTANCES TPM instance(s)"
echo "  Data directory (${SHARED_DIR_PREFIX}*): $SHARED_DATA_ROOT"

# Find existing node directories and remove extras when scaling down
MAX_EXISTING=0
shopt -s nullglob
for _d in "$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}"[0-9]*; do
    [ -d "$_d" ] || continue
    _base="$(basename "$_d")"
    _n="${_base#"$SHARED_DIR_PREFIX"}"
    if [[ "$_n" =~ ^[0-9]+$ ]] && [ "$_n" -gt "$MAX_EXISTING" ]; then
        MAX_EXISTING=$_n
    fi
done
shopt -u nullglob
if [ "$MAX_EXISTING" -gt 0 ] && [ "$NUM_INSTANCES" -lt "$MAX_EXISTING" ]; then
        echo "Scaling down: removing nodes $((NUM_INSTANCES + 1)) through $MAX_EXISTING..."
        for i in $(seq $((NUM_INSTANCES + 1)) $MAX_EXISTING); do
            DIR="$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${i}"
            CONTAINER="tpm2-api-node${i}"
            if [ -d "$DIR" ]; then
                # Stop and remove container if running
                if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
                    echo "  Stopping and removing container ${CONTAINER}..."
                    docker stop "$CONTAINER" 2>/dev/null || true
                    docker rm "$CONTAINER" 2>/dev/null || true
                fi
                echo "  Removing $DIR..."
                rm -rf "$DIR"
            fi
        done
fi

# Create/ensure directories for nodes 1 through NUM_INSTANCES
for i in $(seq 1 $NUM_INSTANCES); do
    DIR="$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${i}"
    TPM_STATE_DIR="${DIR}/tpm_state"
    KEY_BACKUPS_DIR="${DIR}/key_backups"
    METADATA_FILE="${DIR}/signing_keys_metadata.json"
    
    echo "Creating directories for node${i}..."
    mkdir -p "$TPM_STATE_DIR"
    mkdir -p "$KEY_BACKUPS_DIR"
    
    # Initialize signing_keys_metadata.json if it doesn't exist
    if [ ! -f "$METADATA_FILE" ]; then
        echo "{}" > "$METADATA_FILE"
        echo "  ✓ Initialized $METADATA_FILE"
    fi
    
    # Set permissions
    chmod 777 "$DIR" 2>/dev/null || true
    chmod 777 "$TPM_STATE_DIR" 2>/dev/null || true
    chmod 777 "$KEY_BACKUPS_DIR" 2>/dev/null || true
    chmod 666 "$METADATA_FILE" 2>/dev/null || true
    
    echo "✓ Created $DIR, $TPM_STATE_DIR, and $KEY_BACKUPS_DIR"
done

echo ""
echo "Setup complete! Directories created:"
for i in $(seq 1 $NUM_INSTANCES); do
    echo "  - $SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${i}/"
    echo "    ├── tpm_state/"
    echo "    ├── key_backups/"
    echo "    └── signing_keys_metadata.json"
done

# Generate docker-compose.instances.yaml
if [ -f "$INSTANCES_DIR/generate-docker-compose.sh" ]; then
    "$INSTANCES_DIR/generate-docker-compose.sh" "$NUM_INSTANCES"
else
    echo ""
    echo "Warning: generate-docker-compose.sh not found. Run it manually:"
    echo "  ./generate-docker-compose.sh $NUM_INSTANCES"
fi

if [ -f "$INSTANCES_DIR/docker-compose.instances.yaml" ]; then
    echo ""
    echo "Rebuilding TPM Docker image..."
    cd "$PROJECT_ROOT"
    $DOCKER_COMPOSE_CMD -f multiple-instances/docker-compose.instances.yaml build --no-cache
    cd "$INSTANCES_DIR"
    echo "✓ Rebuilt TPM Docker image"
fi

echo ""
echo "You can now start the instances with (from project root):"
echo "  $DOCKER_COMPOSE_CMD -f multiple-instances/docker-compose.instances.yaml up -d"
