#!/usr/bin/env bash
#
# smoke.sh — Quick smoke check of the binary.
# Runs inside the VM (or directly if already in VM).
#
# Usage: bash smoke.sh

set -euo pipefail

if [ -d /vagrant ]; then
    PROJECT_DIR="${PROJECT_DIR:-/vagrant}"
    SCRIPT_DIR="/vagrant/scripts/test"
else
    SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd -P)
    PROJECT_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd -P)
fi

BIN="${BIN:-$PROJECT_DIR/target/release/acme-tiny-rs}"
PASS=0
FAIL=0

ok()   { echo "  OK    $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

check() {
    local desc="$1" expected_rc="${2:-0}"
    shift 2
    local actual_rc=0
    local out
    out="$("$@" 2>&1)" || actual_rc=$?
    if [ "$actual_rc" -eq "$expected_rc" ]; then
        ok "$desc"
    else
        fail "$desc (expected rc=$expected_rc, got rc=$actual_rc)"
        echo "       ${out}" | tail -3
    fi
}

check_out() {
    local desc="$1" pattern="$2" expected_rc="${3:-0}"
    shift 3
    local actual_rc=0
    local out
    out="$("$@" 2>&1)" || actual_rc=$?
    if [ "$actual_rc" -eq "$expected_rc" ] && echo "$out" | grep -qE "$pattern"; then
        ok "$desc"
    else
        fail "$desc (expected rc=$expected_rc, pattern='$pattern')"
        echo "       ${out}" | tail -3
    fi
}

echo "=== Smoke Tests ==="

# ---- Basic execution ----
check     "binary is executable" 0 "$BIN" version
check_out "version format"       '^acme-tiny-rs v[0-9]+\.[0-9]+\.[0-9]+ \([0-9a-f]+, [0-9]+\)$' 0 "$BIN" version

# ---- Help ----
check     "--help exits 0"       0 "$BIN" --help
check_out "--help lists subcommands" 'Commands:' 0 "$BIN" --help
check_out "--help lists ari"     'ari'  0 "$BIN" --help
check_out "--help lists list-ca" 'list-ca' 0 "$BIN" --help
check_out "--help lists version" 'version' 0 "$BIN" --help

# ---- Subcommand help ----
check     "ari --help exits 0"  0 "$BIN" ari --help
check_out "ari --help mentions cert" 'cert' 0 "$BIN" ari --help

# ---- Error exit codes ----
check     "bad arg exits non-zero" 2 "$BIN" --no-such-arg
check     "missing args exits non-zero" 1 "$BIN" --account-key /dev/null
check     "ari missing cert exits non-zero" 1 "$BIN" ari --cert /nonexistent

# ---- Key parsing ----
KEYDIR=$(mktemp -d)
trap 'rm -rf $KEYDIR' EXIT

# RSA account key
openssl genrsa -out "$KEYDIR/rsa.key" 2048 2>/dev/null
check_out "parse RSA account key" 'Parsing account key' 1 \
    "$BIN" --account-key "$KEYDIR/rsa.key" --csr /dev/null --acme-dir /tmp --disable-check

# ECDSA P-256 account key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$KEYDIR/ec.key" 2>/dev/null
check_out "parse ECDSA account key" 'Parsing account key' 1 \
    "$BIN" --account-key "$KEYDIR/ec.key" --csr /dev/null --acme-dir /tmp --disable-check

# ---- CSR parsing ----
openssl req -new -sha256 -key "$KEYDIR/rsa.key" -subj "/" \
    -addext "subjectAltName=DNS:example.com" \
    -out "$KEYDIR/domain.csr" 2>/dev/null
check_out "parse CSR with SAN" 'Found domains: example.com' 1 \
    "$BIN" --account-key "$KEYDIR/rsa.key" --csr "$KEYDIR/domain.csr" --acme-dir /tmp --disable-check

# ---- Summary ----
echo ""
echo "Passed: $PASS  Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
