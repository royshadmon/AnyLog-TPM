#!/bin/bash
set -e

# Configuration via environment variables (with defaults for backward compatibility)
SWTPM_SERVER_PORT=${SWTPM_SERVER_PORT:-2321}
SWTPM_CTRL_PORT=${SWTPM_CTRL_PORT:-2322}
TPM_STATE_DIR=${TPM_STATE_DIR:-/tmp/tpm2-emulated}
SWTPM_LOG_FILE=${SWTPM_LOG_FILE:-/var/log/swtpm.log}

# Start TPM Emulator
echo "Starting DBus..."
mkdir -p /var/run/dbus
rm -f /var/run/dbus/pid /run/dbus/pid /run/dbus/system_bus_socket
dbus-daemon --system --fork

echo "Starting TPM Emulator (swtpm) on port ${SWTPM_SERVER_PORT}..."
mkdir -p ${TPM_STATE_DIR}
chmod 700 ${TPM_STATE_DIR}

swtpm socket --tpmstate dir=${TPM_STATE_DIR} \
             --ctrl type=tcp,port=${SWTPM_CTRL_PORT} \
             --server type=tcp,port=${SWTPM_SERVER_PORT} \
             --flags not-need-init \
             --log level=20 \
             --log file=${SWTPM_LOG_FILE} \
             --tpm2 &

# Wait for the TPM emulator to start
sleep 2

# Wait a bit more for swtpm to be fully ready
sleep 3

# Initialize the TPM (required before first use)
echo "Initializing TPM..."
export TSS2_TCTI="swtpm:host=127.0.0.1,port=${SWTPM_SERVER_PORT}"
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=${SWTPM_SERVER_PORT}"
tpm2_startup -c --tcti=swtpm:host=127.0.0.1,port=${SWTPM_SERVER_PORT} 2>/dev/null || true

# Start the TPM Resource Manager
echo "Starting TPM2-ABRMD..."
tpm2-abrmd --tcti=swtpm:host=127.0.0.1,port=${SWTPM_SERVER_PORT} --allow-root &

# Keep container running
if [[ -z "$1" ]]; then
    echo "No command provided, running a default shell..."
    exec /bin/bash
else
    exec "$@"
fi
