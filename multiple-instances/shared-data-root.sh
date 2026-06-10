#!/bin/bash
# Resolve SHARED_DATA_ROOT — parent directory for per-instance folders (${SHARED_DIR_PREFIX}1, …)
# Source this file, then call load_shared_data_root
#
# Priority:
#   1) SWTPM_SHARED_DATA_ROOT environment variable
#   2) First non-comment line in .instances-path (next to this file)
#   3) Default: this directory (multiple-instances/) — same as before
#
# .instances-path and relative SWTPM_SHARED_DATA_ROOT: non-absolute paths are resolved from
# this directory (multiple-instances/). Use an absolute path to point anywhere on the host.

load_shared_data_root() {
    local _here
    _here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local _f="$_here/.instances-path"

    if [ -n "${SWTPM_SHARED_DATA_ROOT:-}" ]; then
        local _raw="$SWTPM_SHARED_DATA_ROOT"
    elif [ -f "$_f" ]; then
        local _raw
        _raw=$(grep -v '^[[:space:]]*#' "$_f" 2>/dev/null | head -1 | tr -d '\r')
        _raw=$(echo "$_raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    else
        SHARED_DATA_ROOT="$_here"
        export SHARED_DATA_ROOT
        return
    fi

    if [ -z "${_raw:-}" ]; then
        SHARED_DATA_ROOT="$_here"
        export SHARED_DATA_ROOT
        return
    fi

    if [[ "$_raw" != /* ]]; then
        _raw="$_here/$_raw"
    fi
    mkdir -p "$_raw" 2>/dev/null || true
    if [ -d "$_raw" ]; then
        SHARED_DATA_ROOT="$(cd "$_raw" && pwd)"
    else
        SHARED_DATA_ROOT="$_raw"
    fi
    export SHARED_DATA_ROOT
}

# Folder names under SHARED_DATA_ROOT are ${SHARED_DIR_PREFIX}<N> (e.g. shared_dir_node1).
# Source this file, then call load_shared_dir_prefix after load_shared_data_root.
#
# Priority:
#   1) SWTPM_SHARED_DIR_PREFIX environment variable
#   2) First non-comment line in .instances-prefix (next to this file)
#   3) Default: shared_dir_node
#
# The prefix must be a single path component (no '/'). Instance dirs are ${PREFIX}1, ${PREFIX}2, ...

load_shared_dir_prefix() {
    local _here
    _here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local _f="$_here/.instances-prefix"
    local _raw

    if [ -n "${SWTPM_SHARED_DIR_PREFIX:-}" ]; then
        _raw="$SWTPM_SHARED_DIR_PREFIX"
    elif [ -f "$_f" ]; then
        _raw=$(grep -v '^[[:space:]]*#' "$_f" 2>/dev/null | head -1 | tr -d '\r')
        _raw=$(echo "$_raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    else
        SHARED_DIR_PREFIX="shared_dir_node"
        export SHARED_DIR_PREFIX
        return
    fi

    if [ -z "${_raw:-}" ]; then
        SHARED_DIR_PREFIX="shared_dir_node"
        export SHARED_DIR_PREFIX
        return
    fi

    if [[ "$_raw" == */* ]]; then
        echo "shared-data-root: SHARED_DIR_PREFIX must not contain '/' (got: $_raw)" >&2
        exit 1
    fi

    SHARED_DIR_PREFIX="$_raw"
    export SHARED_DIR_PREFIX
}

# Whether generated compose should publish SWTPM server/control ports to the host.
#
# Priority:
#   1) SWTPM_EXPOSE_PORTS environment variable
#   2) First non-comment line in .instances-expose-ports (next to this file)
#   3) Default: true
#
# Accepted true-ish values: 1, true, yes, on
# Accepted false-ish values: 0, false, no, off
load_swtpm_expose_ports() {
    local _here
    _here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local _f="$_here/.instances-expose-ports"
    local _raw=""

    if [ -n "${SWTPM_EXPOSE_PORTS:-}" ]; then
        _raw="$SWTPM_EXPOSE_PORTS"
    elif [ -f "$_f" ]; then
        _raw=$(grep -v '^[[:space:]]*#' "$_f" 2>/dev/null | head -1 | tr -d '\r')
        _raw=$(echo "$_raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    fi

    _raw="$(printf '%s' "${_raw:-true}" | tr '[:upper:]' '[:lower:]')"

    case "$_raw" in
        1|true|yes|on)
            SWTPM_EXPOSE_PORTS_RESOLVED="true"
            ;;
        0|false|no|off|"")
            SWTPM_EXPOSE_PORTS_RESOLVED="false"
            ;;
        *)
            SWTPM_EXPOSE_PORTS_RESOLVED="false"
            ;;
    esac

    export SWTPM_EXPOSE_PORTS_RESOLVED
}
