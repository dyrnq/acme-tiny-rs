#!/usr/bin/env bash
#
# full-regress.sh — Full regression test from scratch.
# Destroys and recreates the Vagrant VM, installs Rust, builds, runs unit tests,
# smoke checks, and integration tests.
#
# Usage: ./scripts/test/full-regress.sh
# shellcheck disable=SC2016
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd -P)
PROJECT_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd -P)

cd "${PROJECT_DIR}"

# ---- Logging ----
LOG_DIR="${PROJECT_DIR}/scripts/test/logs"
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/full-regress-$(date '+%Y%m%d-%H%M%S').log"
exec > >(tee -a "${LOG_FILE}") 2>&1
echo "Log: ${LOG_FILE}"

# ---- SSH run helper (base64 to avoid quoting issues) ----
run_ssh() {
    local cmd="$1"
    local port encoded
    port=$(vagrant ssh-config rust 2>/dev/null | awk '/^  Port / {print $2}')
    encoded=$(echo "$cmd" | base64 -w0)
    ssh -p "${port:-2222}" \
        -i "${PROJECT_DIR}/insecure_private_key" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ServerAliveInterval=10 \
        -o ConnectTimeout=10 \
        vagrant@127.0.0.1 "bash -l -c \"\$(echo ${encoded} | base64 -d)\""
}

echo "=========================================="
echo "  acme-tiny-rs Full Regression Test"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="

# ---- Step 1: Destroy existing VM (if running) ----
echo ""
echo "[1/6] Checking VM status..."
VM_STATE=$(vagrant status rust 2>/dev/null | awk '/^ *rust/{print $2}' || echo "unknown")
if [[ "${VM_STATE}" == "running" || "${VM_STATE}" == "saved" ]]; then
    echo "      VM is '${VM_STATE}', destroying..."
    vagrant destroy -f rust 2>&1 | tail -1
else
    echo "      VM is '${VM_STATE}', skipping destroy."
fi

# ---- Step 2: Start fresh VM ----
echo ""
echo "[2/6] Starting VM + provision..."
# provision.sh self-logs to /vagrant/provision.log
vagrant up rust 2>&1 | grep -E "Installing|Done|apt|rustup|rustc|cargo|Provision|==>|Error|Finished|Rust" || true

# ---- Step 3: Ensure Rust ----
echo ""
echo "[3/6] Ensuring Rust is installed..."
run_ssh '
    if command -v cargo &>/dev/null; then
        echo "cargo: $(cargo --version)"
    else
        echo "cargo not found — installing..."
        export RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
        export RUSTUP_UPDATE_ROOT=https://mirrors.aliyun.com/rustup/rustup
        export RUSTUP_DIST_SERVER=https://mirrors.aliyun.com/rustup
        curl -sSfL "https://mirrors.aliyun.com/rustup/rustup/dist/x86_64-unknown-linux-gnu/rustup-init" -o /tmp/ri &&
            chmod +x /tmp/ri && /tmp/ri -y --profile minimal --default-toolchain stable && rm /tmp/ri
        source /usr/local/cargo/env
        cargo --version
    fi
'

# ---- Step 4: Build + Unit tests ----
echo ""
echo "[4/6] Building + unit tests..."
run_ssh '
    bash /vagrant/scripts/test/build.sh
    echo "--- Unit Tests ---"
    cd /vagrant && cargo test --release 2>&1 | tail -4
'

# ---- Step 5: Smoke check ----
echo ""
echo "[5/6] Smoke check..."
run_ssh 'bash /vagrant/scripts/test/smoke.sh'

# ---- Step 6: Integration tests ----
echo ""
echo "[6/6] Integration tests (pebble)..."
run_ssh '
    sudo bash /vagrant/scripts/test/install_pebble.sh 2>&1 | tail -1
    cd /vagrant/scripts/test && bash integration-test.sh
'

echo ""
echo "=========================================="
echo "  Regression complete! $(date '+%H:%M:%S')"
echo "=========================================="
