#!/bin/bash
# Management script for multiple TPM instances
# Supports clearing TPM data and deleting directories for one or more instances

set -e

INSTANCES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$INSTANCES_DIR")"
# shellcheck source=shared-data-root.sh
source "$INSTANCES_DIR/shared-data-root.sh"
load_shared_data_root
load_shared_dir_prefix

# Run docker-compose from project root
cd "$PROJECT_ROOT"

# Use instances file only (run from project root)
COMPOSE_FILES="-f multiple-instances/docker-compose.instances.yaml"

if command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    DOCKER_COMPOSE_CMD="docker-compose"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 <command> [options]

Commands:
  list                    List all TPM instances and their status
  clear-tpm <nodes>       Clear TPM state data for specified nodes (keeps directories)
  clear-all <nodes>       Clear all data (TPM state + files) for specified nodes (keeps directories)
  delete <nodes>          Delete entire directories for specified nodes
  reset                   Remove all containers and delete ALL instance directories (full wipe)
  stop <nodes>            Stop containers for specified nodes
  start <nodes>           Start containers for specified nodes
  restart <nodes>         Restart containers for specified nodes

Options:
  <nodes>                 Comma-separated list of node numbers (e.g., 1,2,3) or 'all' for all nodes

Examples:
  $0 list
  $0 clear-tpm 1,2
  $0 clear-tpm all
  $0 reset
  $0 stop all
  $0 start 1,2
  $0 restart all

EOF
}

# Function to get list of all node directory numbers (instance index)
get_all_nodes() {
    {
        shopt -s nullglob
        local d _base _n
        for d in "$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}"[0-9]*; do
            [ -d "$d" ] || continue
            _base="$(basename "$d")"
            _n="${_base#"$SHARED_DIR_PREFIX"}"
            if [[ "$_n" =~ ^[0-9]+$ ]]; then
                echo "$_n"
            fi
        done
        shopt -u nullglob

        docker ps -a --format '{{.Names}}' 2>/dev/null \
            | sed -n 's/^tpm2-api-node\([0-9][0-9]*\)$/\1/p' || true
    } | sort -n -u
}

get_compose_services() {
    if [ ! -f "$INSTANCES_DIR/docker-compose.instances.yaml" ]; then
        return
    fi

    $DOCKER_COMPOSE_CMD $COMPOSE_FILES ps --services 2>/dev/null || true
}

# Function to parse node list
parse_nodes() {
    local nodes_arg=$1
    if [ "$nodes_arg" = "all" ]; then
        get_all_nodes | tr '\n' ' '
    else
        echo "$nodes_arg" | tr ',' ' '
    fi
}

# Function to check if node exists
node_exists() {
    local node=$1
    [ -d "$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${node}" ]
}

# Function to stop containers
stop_containers() {
    local nodes=$1
    print_info "Stopping containers..."
    
    for node in $nodes; do
        local service="tpm2-api-node${node}"
        local container="tpm2-api-node${node}"
        
        if get_compose_services | grep -q "^${service}$"; then
            print_info "Stopping ${service}..."
            $DOCKER_COMPOSE_CMD $COMPOSE_FILES stop "$service" 2>/dev/null || true
            print_success "Stopped ${service}"
        elif docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            print_info "Stopping ${container}..."
            docker stop "$container" 2>/dev/null || true
            print_success "Stopped ${container}"
        else
            print_warning "Service/container ${service} not found, skipping..."
        fi
    done
}

# Function to start containers
start_containers() {
    local nodes=$1
    print_info "Starting containers..."
    
    for node in $nodes; do
        local service="tpm2-api-node${node}"
        
        if [ ! -f "$INSTANCES_DIR/docker-compose.instances.yaml" ] || ! $DOCKER_COMPOSE_CMD $COMPOSE_FILES config --services 2>/dev/null | grep -q "^${service}$"; then
            print_warning "Service ${service} not found in docker-compose, skipping..."
            continue
        fi
        
        print_info "Starting ${service}..."
        if $DOCKER_COMPOSE_CMD $COMPOSE_FILES up -d "$service" >/dev/null 2>&1; then
            print_success "Started ${service}"
        else
            print_error "Failed to start ${service}"
        fi
    done
}

# Function to clear TPM state only
clear_tpm_state() {
    local nodes=$1
    local confirm=$2
    
    if [ "$confirm" != "yes" ]; then
        print_warning "This will clear TPM state data (keys, contexts) for the specified nodes."
        print_warning "Files in shared directories will be preserved."
        echo ""
        read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirm_input
        if [ "$confirm_input" != "yes" ]; then
            print_info "Operation cancelled."
            return
        fi
    fi
    
    print_info "Clearing TPM state data..."
    
    for node in $nodes; do
        if ! node_exists "$node"; then
            print_warning "Node $node does not exist, skipping..."
            continue
        fi
        
        local tpm_state_dir="$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${node}/tpm_state"
        local container="tpm2-api-node${node}"
        
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            print_info "Stopping and removing ${container} (needed for TPM state to regen on restart)..."
            docker stop "$container" 2>/dev/null || true
            docker rm "$container" 2>/dev/null || true
        fi
        
        if [ -d "$tpm_state_dir" ]; then
            print_info "Clearing TPM state for node${node}..."
            find "$tpm_state_dir" -type f -delete 2>/dev/null || true
            find "$tpm_state_dir" -mindepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
            print_success "Cleared TPM state for node${node}"
        else
            print_warning "TPM state directory for node${node} does not exist, skipping..."
        fi
    done
    
    print_success "TPM state clearing complete!"
}

# Function to clear all data (TPM state + files)
clear_all_data() {
    local nodes=$1
    local confirm=$2
    
    if [ "$confirm" != "yes" ]; then
        print_warning "This will delete ALL data for the specified nodes."
        echo ""
        read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirm_input
        if [ "$confirm_input" != "yes" ]; then
            print_info "Operation cancelled."
            return
        fi
    fi
    
    print_info "Clearing all data..."
    
    for node in $nodes; do
        if ! node_exists "$node"; then
            print_warning "Node $node does not exist, skipping..."
            continue
        fi
        
        local shared_dir="$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${node}"
        local tpm_state_dir="${shared_dir}/tpm_state"
        local key_backups_dir="${shared_dir}/key_backups"
        local container="tpm2-api-node${node}"
        
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            print_info "Stopping and removing ${container} (needed for TPM state to regen on restart)..."
            docker stop "$container" 2>/dev/null || true
            docker rm "$container" 2>/dev/null || true
        fi
        
        print_info "Clearing all data for node${node}..."
        [ -d "$shared_dir" ] && find "$shared_dir" -maxdepth 1 -type f -delete 2>/dev/null || true
        [ -d "$tpm_state_dir" ] && find "$tpm_state_dir" -type f -delete 2>/dev/null || true
        [ -d "$tpm_state_dir" ] && find "$tpm_state_dir" -mindepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
        [ -d "$key_backups_dir" ] && find "$key_backups_dir" -type f -delete 2>/dev/null || true
        print_success "Cleared all data for node${node}"
    done
    
    print_success "All data clearing complete!"
}

# Function to delete entire directories
delete_directories() {
    local nodes=$1
    local confirm=$2
    
    if [ "$confirm" != "yes" ]; then
        print_error "⚠️  WARNING: This will PERMANENTLY DELETE entire directories!"
        echo ""
        read -p "Are you absolutely sure? (type 'DELETE' to confirm): " confirm_input
        if [ "$confirm_input" != "DELETE" ]; then
            print_info "Operation cancelled."
            return
        fi
    fi
    
    print_info "Deleting directories..."
    
    for node in $nodes; do
        if ! node_exists "$node"; then
            print_warning "Node $node does not exist, skipping..."
            continue
        fi
        
        local shared_dir="$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${node}"
        local container="tpm2-api-node${node}"
        
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            print_info "Stopping and removing ${container}..."
            docker stop "$container" 2>/dev/null || true
            docker rm "$container" 2>/dev/null || true
        fi
        
        if [ -d "$shared_dir" ]; then
            rm -rf "$shared_dir"
            print_success "Deleted ${shared_dir}"
        fi
    done
    
    print_success "Directory deletion complete!"
}

# Function to reset everything: take down containers, delete all directories and generated files
reset_all() {
    local confirm=$1
    
    if [ "$confirm" != "yes" ]; then
        print_error "⚠️  RESET will remove ALL containers and delete ALL instance data!"
        print_warning "This includes:"
        print_warning "  - All TPM instance containers"
        print_warning "  - All ${SHARED_DIR_PREFIX}* instance directories"
        print_warning "  - docker-compose.instances.yaml and .num_instances"
        echo ""
        read -p "Are you sure? (type 'yes' to confirm): " confirm_input
        if [ "$confirm_input" != "yes" ]; then
            print_info "Operation cancelled."
            return
        fi
    fi
    
    print_info "Resetting all TPM instances..."
    
    # Take down containers
    if [ -f "$INSTANCES_DIR/docker-compose.instances.yaml" ]; then
        print_info "Stopping and removing containers..."
        $DOCKER_COMPOSE_CMD $COMPOSE_FILES down 2>/dev/null || true
        print_success "Containers removed"
    fi
    
    # Delete all instance directories for this prefix
    shopt -s nullglob
    for dir in "$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}"[0-9]*; do
        if [ -d "$dir" ]; then
            print_info "Deleting $(basename "$dir")..."
            rm -rf "$dir"
            print_success "Deleted $(basename "$dir")"
        fi
    done
    shopt -u nullglob
    
    # Remove generated files
    [ -f "$INSTANCES_DIR/docker-compose.instances.yaml" ] && rm -f "$INSTANCES_DIR/docker-compose.instances.yaml" && print_success "Removed docker-compose.instances.yaml"
    [ -f "$INSTANCES_DIR/.num_instances" ] && rm -f "$INSTANCES_DIR/.num_instances" && print_success "Removed .num_instances"
    
    print_success "Reset complete! Run ./setup-multiple-instances.sh <N> to start fresh."
}

# Function to list all instances
list_instances() {
    print_info "TPM Instances Status:"
    echo ""
    
    local nodes=$(get_all_nodes)
    
    if [ -z "$nodes" ]; then
        print_warning "No TPM instances found under $SHARED_DATA_ROOT/"
        return
    fi
    
    printf "%-10s %-20s %-15s %-15s %-10s\n" "Node" "Container" "Status" "API Port" "Directory"
    echo "----------------------------------------------------------------------------"
    
    for node in $nodes; do
        local container="tpm2-api-node${node}"
        local shared_dir="$SHARED_DATA_ROOT/${SHARED_DIR_PREFIX}${node}"
        local api_port=$((8000 + node))
        
        local container_status="Not found"
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
            container_status="Running"
        elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
            container_status="Stopped"
        fi
        
        local dir_status="Missing"
        if [ -d "$shared_dir" ]; then
            local file_count=$(find "$shared_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
            dir_status="Exists ($file_count files)"
        fi
        
        printf "%-10s %-20s %-15s %-15s %-10s\n" "node${node}" "$container" "$container_status" "$api_port" "$dir_status"
    done
    
    echo ""
    print_info "To manage: $0 <command> <nodes>"
}

# Main
if [ $# -lt 1 ]; then
    show_usage
    exit 1
fi

COMMAND=$1
shift

case "$COMMAND" in
    list)
        list_instances
        ;;
    clear-tpm)
        [ $# -lt 1 ] && { print_error "Specify node(s)"; exit 1; }
        clear_tpm_state "$(parse_nodes "$1")"
        ;;
    clear-all)
        [ $# -lt 1 ] && { print_error "Specify node(s)"; exit 1; }
        clear_all_data "$(parse_nodes "$1")"
        ;;
    delete)
        [ $# -lt 1 ] && { print_error "Specify node(s)"; exit 1; }
        delete_directories "$(parse_nodes "$1")"
        ;;
    reset)
        reset_all ""
        ;;
    stop)
        [ $# -lt 1 ] && { print_error "Specify node(s)"; exit 1; }
        stop_containers "$(parse_nodes "$1")"
        ;;
    start)
        [ $# -lt 1 ] && { print_error "Specify node(s)"; exit 1; }
        start_containers "$(parse_nodes "$1")"
        ;;
    restart)
        [ $# -lt 1 ] && { print_error "Specify node(s)"; exit 1; }
        stop_containers "$(parse_nodes "$1")"
        sleep 1
        start_containers "$(parse_nodes "$1")"
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac
