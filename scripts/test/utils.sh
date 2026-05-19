#!/usr/bin/env bash
# Test utilities for acme-tiny-rs integration tests
# Source this file in test scripts: source "$(dirname "$0")/utils.sh"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BINARY="${PROJECT_DIR}/target/release/acme-tiny-rs"

# Defaults
PEBBLE_DIR="${PEBBLE_DIR:-/opt/pebble}"
PEBBLE_BIN="${PEBBLE_DIR}/pebble"
CHALLTESTSRV_BIN="${PEBBLE_DIR}/pebble-challtestsrv"
PEBBLE_CONFIG="${PEBBLE_DIR}/pebble-config.json"
PEBBLE_CERT="${PEBBLE_DIR}/certs/pebble.crt"

TEST_DOMAIN="localhost"
DIRECTORY_URL="https://localhost:14000/dir"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; exit 1; }

# Generate test keys in a temp directory
gen_test_keys() {
    local dir="${1:-$(mktemp -d)}"
    mkdir -p "${dir}"

    # Account key (RSA)
    openssl genrsa -out "${dir}/account.key" 2048 2>/dev/null

    # ECDSA account key
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "${dir}/account_ec.key" 2>/dev/null

    # Domain key (RSA)
    openssl genrsa -out "${dir}/domain.key" 2048 2>/dev/null

    # Valid domain CSR (SAN)
    openssl req -new -sha256 -key "${dir}/domain.key" \
        -subj "/" \
        -addext "subjectAltName=DNS:${TEST_DOMAIN}" \
        -out "${dir}/domain.csr" 2>/dev/null

    # CN-only CSR (for testing — Pebble does NOT support CN-only CSRs per RFC 8555)
    openssl req -new -sha256 -key "${dir}/domain.key" \
        -subj "/CN=${TEST_DOMAIN}" \
        -out "${dir}/cn.csr" 2>/dev/null

    # CN + SAN CSR (both CN and SAN contain the same domain — recommended practice)
    openssl req -new -sha256 -key "${dir}/domain.key" \
        -subj "/CN=${TEST_DOMAIN}" \
        -addext "subjectAltName=DNS:${TEST_DOMAIN}" \
        -out "${dir}/cn_san.csr" 2>/dev/null

    # Invalid domain CSR (unicode characters)
    printf "[SAN]\nsubjectAltName=DNS:\xC3\xA0\xC2\xB2\xC2\xA0.com\n" > "${dir}/invalid.conf"
    openssl req -new -sha256 -key "${dir}/domain.key" \
        -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf "${dir}/invalid.conf" 2>/dev/null || echo) \
        -out "${dir}/invalid.csr" 2>/dev/null || true

    # Non-existent domain CSR
    printf "[SAN]\nsubjectAltName=DNS:this-domain-does-not-exist-12345.com\n" > "${dir}/nonexistent.conf"
    openssl req -new -sha256 -key "${dir}/domain.key" \
        -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf "${dir}/nonexistent.conf" 2>/dev/null || echo) \
        -out "${dir}/nonexistent.csr" 2>/dev/null || true

    # Account key used as domain key CSR
    openssl req -new -sha256 -key "${dir}/account.key" \
        -subj "/" \
        -addext "subjectAltName=DNS:${TEST_DOMAIN}" \
        -out "${dir}/account.csr" 2>/dev/null

    echo "${dir}"
}

# Start pebble server
start_pebble() {
    if [ ! -x "${PEBBLE_BIN}" ]; then
        echo "Pebble not found at ${PEBBLE_BIN}. Run install_pebble.sh first."
        return 1
    fi

    # Allow authz reuse and set nonce reject rate
    export PEBBLE_AUTHZREUSE=100
    export PEBBLE_WFE_NONCEREJECT="${1:-0}"
    export PEBBLE_VA_ALWAYS_VALID=1

    # Trust pebble cert
    export SSL_CERT_FILE="${PEBBLE_CERT}"

    # Use installed pebble config (includes EAB key for testing)
    PEBBLE_CONFIG="${PEBBLE_DIR}/pebble-config.json"

    echo "Starting pebble..."
    "${PEBBLE_BIN}" -config "${PEBBLE_CONFIG}" &
    PEBBLE_PID=$!

    # Wait for pebble to be ready
    local max_wait=20
    local waited=0
    while [ $waited -lt $max_wait ]; do
        if curl -sk --noproxy '*' --connect-timeout 2 "${DIRECTORY_URL}" > /dev/null 2>&1; then
            echo "Pebble ready (PID: ${PEBBLE_PID})"
            return 0
        fi
        sleep 0.5
        waited=$((waited + 1))
    done

    echo "ERROR: Pebble failed to start"
    kill ${PEBBLE_PID} 2>/dev/null || true
    return 1
}

# Start local HTTP challenge file server
start_challenge_server() {
    local port="${1:-5002}"
    local dir="${2:-$(mktemp -d)}"

    mkdir -p "${dir}/.well-known/acme-challenge"

    echo "Starting challenge server on port ${port}..."
    cd "${dir}" && python3 -m http.server "${port}" --bind 127.0.0.1 &
    CHALLENGE_PID=$!
    cd - > /dev/null

    # Verify it's serving
    local test_file="${dir}/.well-known/acme-challenge/test.txt"
    echo "ok" > "${test_file}"
    local max_wait=10
    local waited=0
    while [ $waited -lt $max_wait ]; do
        if curl -s --noproxy '*' --connect-timeout 2 "http://localhost:${port}/.well-known/acme-challenge/test.txt" 2>/dev/null | grep -q ok; then
            echo "Challenge server ready (PID: ${CHALLENGE_PID})"
            rm -f "${test_file}"
            return 0
        fi
        sleep 0.5
        waited=$((waited + 1))
    done

    echo "ERROR: Challenge server failed to start"
    kill ${CHALLENGE_PID} 2>/dev/null || true
    rm -f "${test_file}"
    return 1
}

# Stop pebble, challenge server, and challtestsrv
cleanup_servers() {
    [ -n "${PEBBLE_PID:-}" ] && kill ${PEBBLE_PID} 2>/dev/null || true
    [ -n "${CHALLENGE_PID:-}" ] && kill ${CHALLENGE_PID} 2>/dev/null || true
    [ -n "${CHALLTESTSRV_PID:-}" ] && kill ${CHALLTESTSRV_PID} 2>/dev/null || true
    wait 2>/dev/null || true
}

# Start pebble-challtestsrv for DNS-01 challenge testing
start_challtestsrv() {
    if [ ! -x "${CHALLTESTSRV_BIN}" ]; then
        echo "pebble-challtestsrv not found at ${CHALLTESTSRV_BIN}. Skipping DNS tests."
        return 1
    fi
    echo "Starting pebble-challtestsrv..."
    "${CHALLTESTSRV_BIN}" -dnsserver ":8053" -management ":8055" -http01 "" -https01 "" -tlsalpn01 "" &
    CHALLTESTSRV_PID=$!
    sleep 2
    echo "pebble-challtestsrv ready (PID: ${CHALLTESTSRV_PID})"
    return 0
}

# Start pebble with DNS server for DNS-01 testing
start_pebble_dns() {
    if [ ! -x "${PEBBLE_BIN}" ]; then
        echo "Pebble not found at ${PEBBLE_BIN}. Run install_pebble.sh first."
        return 1
    fi
    export PEBBLE_AUTHZREUSE=100
    export PEBBLE_WFE_NONCEREJECT="${1:-0}"
    # Enable real DNS validation against challtestsrv
    export PEBBLE_VA_ALWAYS_VALID=0
    export SSL_CERT_FILE="${PEBBLE_CERT}"
    PEBBLE_CONFIG="${PEBBLE_DIR}/pebble-config.json"
    echo "Starting pebble (DNS mode)..."
    "${PEBBLE_BIN}" -config "${PEBBLE_CONFIG}" -dnsserver ":8053" &
    PEBBLE_PID=$!
    local max_wait=20
    local waited=0
    while [ $waited -lt $max_wait ]; do
        if curl -sk --noproxy '*' --connect-timeout 2 "${DIRECTORY_URL}" > /dev/null 2>&1; then
            echo "Pebble ready (PID: ${PEBBLE_PID})"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "ERROR: Pebble DNS mode failed to start"
    cleanup_servers
    return 1
}

# Verify a certificate contains expected issuer
verify_cert() {
    local cert_file="$1"
    local expected_issuer="${2:-Pebble}"
    openssl x509 -in "${cert_file}" -text -noout 2>/dev/null | grep -q "${expected_issuer}"
}
