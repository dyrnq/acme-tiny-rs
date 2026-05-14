#!/usr/bin/env bash
#
# build.sh — Compile acme-tiny-rs in release mode.
# Runs inside the VM (or directly if already in VM).
#
# Usage: bash build.sh

set -euo pipefail

if [ -d /vagrant ]; then
    PROJECT_DIR="${PROJECT_DIR:-/vagrant}"
    SCRIPT_DIR="/vagrant/scripts/test"
else
    SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd -P)
    PROJECT_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd -P)
fi


cd "${PROJECT_DIR}"

echo "--- Build ---"
cargo build --release 2>&1 | grep -E "Compiling|Finished|warning" || true
