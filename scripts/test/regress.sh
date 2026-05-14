#!/usr/bin/env bash
#
# regress.sh — Quick regression test (build + unit tests + smoke + integration).
# Assumes VM is already running and Rust is installed.
# For full VM rebuild, use full-regress.sh.
#
# Usage: ./scripts/test/regress.sh [--local]

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd -P)
PROJECT_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd -P)

# ---- Parse flags ----
LOCAL=false
for arg in "$@"; do
    case "$arg" in
        --local) LOCAL=true ;;
        *) echo "Unknown arg: $arg" >&2; exit 2 ;;
    esac
done

cd "${PROJECT_DIR}"

# ---- Logging ----
LOG_DIR="${PROJECT_DIR}/scripts/test/logs"
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/regress-$(date '+%Y%m%d-%H%M%S').log"
exec > >(tee -a "${LOG_FILE}") 2>&1
echo "Log: ${LOG_FILE}"

# ---- Run a command (locally or via SSH) ----
# __ROOT__ in command strings is replaced with the project root path.
# Uses base64 encoding to avoid shell quoting issues over SSH.
run() {
    local cmd="$1"
    if $LOCAL; then
        cmd="${cmd//__ROOT__/${PROJECT_DIR}}"
        bash -l -c "$cmd"
    else
        cmd="${cmd//__ROOT__//vagrant}"
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
    fi
}

echo "=========================================="
echo "  acme-tiny-rs Regression Test"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="

# ---- Step 1/3: Build + Unit tests ----
echo ""
echo "[1/3] Building + unit tests..."
run '
    bash __ROOT__/scripts/test/build.sh
    echo "--- Unit Tests ---"
    cd __ROOT__ && cargo test --release 2>&1 | tail -4
'

# ---- Step 2/3: Smoke check ----
echo ""
echo "[2/3] Smoke check..."
run 'bash __ROOT__/scripts/test/smoke.sh'

# ---- Step 3/3: Integration tests ----
echo ""
echo "[3/3] Integration tests (pebble)..."
run '
    sudo bash __ROOT__/scripts/test/install_pebble.sh 2>&1 | tail -1
    cd __ROOT__/scripts/test && bash integration-test.sh
'

echo ""
echo "=========================================="
echo "  Regression complete! $(date '+%H:%M:%S')"
echo "=========================================="
