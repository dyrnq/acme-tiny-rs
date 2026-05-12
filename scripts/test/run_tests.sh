#!/usr/bin/env bash
# acme-tiny-rs integration test suite
# Usage: ./run_tests.sh [--pebble-dir /opt/pebble]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

source "${SCRIPT_DIR}/utils.sh"

# --- Cleanup stale processes ---
kill $(pgrep -f pebble) 2>/dev/null || true
fuser -k 5002/tcp 2>/dev/null || true
fuser -k 14000/tcp 2>/dev/null || true
sleep 1

# --- Test state ---
PASSED=0
FAILED=0
TMPDIR=$(mktemp -d)
trap 'cleanup_servers; rm -rf ${TMPDIR}' EXIT

run_test() {
    local name="$1"
    shift
    echo -n "  ${name}... "
    if "$@" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# --- Setup ---
echo "=== acme-tiny-rs Integration Tests ==="
echo ""

if [ ! -x "${BINARY}" ]; then
    echo "Building acme-tiny-rs..."
    cd "${PROJECT_DIR}" && cargo build --release
fi

if [ ! -x "${PEBBLE_BIN}" ]; then
    echo "Installing pebble..."
    bash "${SCRIPT_DIR}/install_pebble.sh"
fi

echo "Generating test keys..."
KEYS_DIR=$(gen_test_keys "${TMPDIR}/keys")

echo "Starting test servers..."
start_pebble || exit 1
start_challenge_server 5002 "${TMPDIR}/challenges" || exit 1

CHECK_PORT=5002
BASE_ARGS="--directory-url ${DIRECTORY_URL} --check-port ${CHECK_PORT} --insecure --agree-tos"

# Helper for cert verification (usable in bash -c)
cert_ok() { openssl x509 -in "$1" -text -noout 2>/dev/null | grep -q "${2:-Pebble}"; }
export -f cert_ok

echo ""
echo "--- Tests ---"
echo ""

# ==== CLI tests ====

run_test "CLI help" \
    "${BINARY}" --help

run_test "CLI missing required args" \
    bash -c "! ${BINARY} --account-key /dev/null 2>&1"

# ==== Key parsing tests ====

run_test "Parse RSA account key" \
    bash -c "${BINARY} --account-key ${KEYS_DIR}/account.key --csr /dev/null --acme-dir /tmp --disable-check 2>&1 | grep -q 'Parsing account key'"

run_test "Parse ECDSA account key" \
    bash -c "${BINARY} --account-key ${KEYS_DIR}/account_ec.key --csr /dev/null --acme-dir /tmp --disable-check 2>&1 | grep -q 'Parsing account key'"

run_test "Reject missing account key" \
    bash -c "! ${BINARY} --account-key /nonexistent.key --csr /dev/null --acme-dir /tmp 2>&1"

# ==== CSR parsing tests ====

run_test "Parse CSR with SAN domains" \
    bash -c "${BINARY} --account-key ${KEYS_DIR}/account.key --csr ${KEYS_DIR}/domain.csr --acme-dir /tmp --disable-check 2>&1 | grep -q 'Found domains: ${TEST_DOMAIN}'"

run_test "Reject missing CSR" \
    bash -c "! ${BINARY} --account-key ${KEYS_DIR}/account.key --csr /nonexistent.csr --acme-dir /tmp 2>&1"

# ==== Full certificate issuance ====

run_test "Issue certificate via pebble" \
    bash -c "
        ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            > ${TMPDIR}/signed.crt 2>/dev/null && \
        cert_ok ${TMPDIR}/signed.crt 'Pebble'
    "

run_test "Issue certificate with ECDSA account key" \
    bash -c "
        ${BINARY} \
            --account-key ${KEYS_DIR}/account_ec.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            > ${TMPDIR}/signed_ec.crt 2>/dev/null && \
        cert_ok ${TMPDIR}/signed_ec.crt 'Pebble'
    "

run_test "Issue certificate (quiet mode)" \
    bash -c "
        ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} --quiet \
            > ${TMPDIR}/signed_quiet.crt 2>/dev/null && \
        cert_ok ${TMPDIR}/signed_quiet.crt 'Pebble'
    "

# ==== Already-valid authorizations ====

run_test "Skip already-verified domains" \
    bash -c "
        ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            > ${TMPDIR}/signed2.crt 2>/dev/null && \
        cert_ok ${TMPDIR}/signed2.crt 'Pebble'
    "

# ==== Contact details ====

run_test "Set contact details" \
    bash -c "
        ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} --contact mailto:test@example.com --disable-check \
            > ${TMPDIR}/signed_contact.crt 2>/dev/null && \
        cert_ok ${TMPDIR}/signed_contact.crt 'Pebble'
    "

# ==== Error cases ====

run_test "Error on non-existent domain" \
    bash -c "
        ! ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/nonexistent.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            > /dev/null 2>&1
    "

# Verify challenge files are cleaned up after failure
run_test "Cleanup challenge files on failure" \
    bash -c "
        ACME_DIR=${TMPDIR}/challenges/.well-known/acme-challenge/
        # Run with a CSR that will create then fail a challenge
        ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/nonexistent.csr \
            --acme-dir \${ACME_DIR} \
            ${BASE_ARGS} \
            > /dev/null 2>&1 || true
        # Challenge directory should be empty after failure
        remaining=\$(ls -A \${ACME_DIR} 2>/dev/null | wc -l)
        [ \"\${remaining}\" -eq 0 ]
    "

# ==== Summary ====

echo ""
echo "--- Results ---"
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo ""

if [ ${FAILED} -gt 0 ]; then
    exit 1
fi
exit 0
