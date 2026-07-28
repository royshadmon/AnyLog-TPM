#!/bin/bash
set -e

# Configuration via environment variables (with defaults for backward compatibility)
SWTPM_SERVER_PORT=${SWTPM_SERVER_PORT:-2321}
SWTPM_CTRL_PORT=${SWTPM_CTRL_PORT:-2322}
TPM_STATE_DIR=${TPM_STATE_DIR:-/tmp/tpm2-emulated}
SWTPM_LOG_FILE=${SWTPM_LOG_FILE:-/var/log/swtpm.log}
USE_SWTPM=${USE_SWTPM:-1}

# Start TPM Emulator unless the container is configured to use a hardware TPM.
echo "Starting DBus..."
mkdir -p /var/run/dbus
rm -f /var/run/dbus/pid /run/dbus/pid /run/dbus/system_bus_socket
dbus-daemon --system --fork

if [[ "${USE_SWTPM}" == "1" ]]; then
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

    sleep 2
    sleep 3

    echo "Initializing TPM..."
    export TSS2_TCTI="${TSS2_TCTI:-swtpm:host=127.0.0.1,port=${SWTPM_SERVER_PORT}}"
    export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-swtpm:host=127.0.0.1,port=${SWTPM_SERVER_PORT}}"
    export TPM2OPENSSL_TCTI="${TPM2OPENSSL_TCTI:-swtpm:host=127.0.0.1,port=${SWTPM_SERVER_PORT}}"
    tpm2_startup -c --tcti="${TSS2_TCTI}" 2>/dev/null || true

    echo "Starting TPM2-ABRMD..."
    tpm2-abrmd --tcti="${TSS2_TCTI}" --allow-root &
else
    echo "USE_SWTPM=0, expecting a hardware TPM."
    export TSS2_TCTI="${TSS2_TCTI:-device:/dev/tpmrm0}"
    export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-${TSS2_TCTI}}"
    export TPM2OPENSSL_TCTI="${TPM2OPENSSL_TCTI:-${TSS2_TCTI}}"
    echo "Using TSS2_TCTI=${TSS2_TCTI}"
fi

# Keep container running
if [[ -z "$1" ]]; then
    echo "No command provided, running a default shell..."
    exec /bin/bash
else
    exec "$@"
fi
