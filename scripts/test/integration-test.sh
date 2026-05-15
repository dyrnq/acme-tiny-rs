#!/usr/bin/env bash
# acme-tiny-rs integration test suite
# Usage: ./integration-test.sh [--pebble-dir /opt/pebble]
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
    bash "${SCRIPT_DIR}/build.sh"
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
# Prevent proxy from sending localhost traffic to external proxy
export no_proxy="localhost,127.0.0.1,.local"
export NO_PROXY="localhost,127.0.0.1,.local"
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

run_test "Parse CN-only CSR" \
    bash -c "${BINARY} --account-key ${KEYS_DIR}/account.key --csr ${KEYS_DIR}/cn.csr --acme-dir /tmp --disable-check 2>&1 | grep -q 'Found domains: ${TEST_DOMAIN}'"

run_test "Parse CN+SAN CSR (dedup)" \
    bash -c "${BINARY} --account-key ${KEYS_DIR}/account.key --csr ${KEYS_DIR}/cn_san.csr --acme-dir /tmp --disable-check 2>&1 | grep -q 'Found domains: ${TEST_DOMAIN}'"

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

# ==== Hooks ====

# Create a test hook script
HOOK_SCRIPT="${TMPDIR}/test_hook.sh"
cat > "${HOOK_SCRIPT}" << 'HOOKEOF'
#!/bin/sh
case "${ACME_HOOK:-}" in
    pre)  echo "pre-hook-ran" ;;
    post) echo "post-hook-ran" ;;
    deploy) echo "deploy-hook-ran" ;;
esac
HOOKEOF
chmod +x "${HOOK_SCRIPT}"

run_test "pre-hook executes before ACME flow" \
    bash -c "
        ACME_HOOK=pre ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            --pre-hook \"ACME_HOOK=pre ${HOOK_SCRIPT}\" \
            > ${TMPDIR}/hook_test.crt 2>/dev/null && \
        grep -q 'pre-hook-ran' ${TMPDIR}/hook_test.crt
    "

run_test "deploy-hook executes after cert issuance" \
    bash -c "
        ACME_HOOK=deploy ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            --deploy-hook \"ACME_HOOK=deploy ${HOOK_SCRIPT}\" \
            > ${TMPDIR}/hook_deploy.crt 2>/dev/null && \
        grep -q 'deploy-hook-ran' ${TMPDIR}/hook_deploy.crt
    "

run_test "post-hook runs even on failure" \
    bash -c "
        ACME_HOOK=post ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/nonexistent.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            --post-hook \"ACME_HOOK=post ${HOOK_SCRIPT}\" \
            > ${TMPDIR}/hook_post.log 2>&1 || true
        grep -q 'post-hook-ran' ${TMPDIR}/hook_post.log
    "

# ==== Subcommands ====

run_test "version subcommand" \
    bash -c "
        ${BINARY} version > ${TMPDIR}/version.out 2>/dev/null && \
        grep -q 'acme-tiny-rs v' ${TMPDIR}/version.out
    "

run_test "ari subcommand --help" \
    bash -c "
        ${BINARY} ari --help 2>/dev/null | grep -q 'cert'
    "

# ==== TLS version compatibility ====

run_test "TLS 1.3 inspect" \
    bash -c "
        openssl req -x509 -newkey rsa:2048 -sha256 -keyout ${TMPDIR}/tls13.key -out ${TMPDIR}/tls13.crt -days 1 -subj /CN=tls13 -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/tls13.crt -key ${TMPDIR}/tls13.key -port 5450 -tls1_3 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} inspect -d localhost:5450 -k 2>/dev/null | grep -q 'tls13'
        kill \$PID 2>/dev/null
    "

run_test "TLS 1.3 dump" \
    bash -c "
        openssl req -x509 -newkey rsa:2048 -sha256 -keyout ${TMPDIR}/tls13d.key -out ${TMPDIR}/tls13d.crt -days 1 -subj /CN=tls13d -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/tls13d.crt -key ${TMPDIR}/tls13d.key -port 5451 -tls1_3 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} dump localhost:5451 -k 2>/dev/null | grep -q 'CERTIFICATE'
        kill \$PID 2>/dev/null
    "


run_test "inspect subcommand --help" \
    bash -c "
        ${BINARY} inspect --help 2>/dev/null | grep -q 'domain'
    "

run_test "inspect subcommand table output" \
    bash -c "
        openssl req -x509 -newkey rsa:2048 -keyout ${TMPDIR}/insp.key -out ${TMPDIR}/insp.crt -days 1 -subj /CN=inspect-test -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/insp.crt -key ${TMPDIR}/insp.key -port 5443 -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} inspect -d localhost:5443 -k 2>/dev/null | grep -q 'inspect-test'
        kill \$PID 2>/dev/null
    "

run_test "inspect subcommand JSON output" \
    bash -c "
        openssl req -x509 -newkey rsa:2048 -keyout ${TMPDIR}/insp2.key -out ${TMPDIR}/insp2.crt -days 1 -subj /CN=json-inspect -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/insp2.crt -key ${TMPDIR}/insp2.key -port 5444 -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} inspect -d localhost:5444 --json -k 2>/dev/null | grep -q 'subject_cn'
        kill \$PID 2>/dev/null
    "

run_test "inspect subcommand -k insecure flag" \
    bash -c "
        openssl req -x509 -newkey rsa:2048 -keyout ${TMPDIR}/insk.key -out ${TMPDIR}/insk.crt -days 1 -subj /CN=insecure-test -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/insk.crt -key ${TMPDIR}/insk.key -port 5445 -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        # Without -k should fail, with -k should succeed
        ! ${BINARY} inspect -d localhost:5445 2>/dev/null | grep -q 'insecure-test' && \
        ${BINARY} inspect -d localhost:5445 -k 2>/dev/null | grep -q 'insecure-test'
        RET=\$?
        kill \$PID 2>/dev/null
        exit \$RET
    "

run_test "inspect subcommand --lint (detects issues)" \
    bash -c "
        # RSA 2048 is fine for TLS, but 5-day expiry triggers lint
        openssl req -x509 -newkey rsa:2048 -sha256 -keyout ${TMPDIR}/lintwarn.key -out ${TMPDIR}/lintwarn.crt -days 5 -subj /CN=lint-warn -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/lintwarn.crt -key ${TMPDIR}/lintwarn.key -port 5446 -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} inspect -d localhost:5446 -k --lint 2>/dev/null | grep -q 'Expires in less than 30'
        RET=\$?
        kill \$PID 2>/dev/null
        exit \$RET
    "

run_test "inspect subcommand --lint (clean cert)" \
    bash -c "
        # RSA 4096 + SHA-256 = strong cert, should report OK
        openssl req -x509 -newkey rsa:4096 -sha256 -keyout ${TMPDIR}/lintok.key -out ${TMPDIR}/lintok.crt -days 365 -subj /CN=lint-ok -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/lintok.crt -key ${TMPDIR}/lintok.key -port 5447 -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} inspect -d localhost:5447 -k --lint 2>/dev/null | grep -q 'localhost.*OK'
        RET=\$?
        kill \$PID 2>/dev/null
        exit \$RET
    "

run_test "inspect --lint --json (warnings array)" \
    bash -c "
        openssl req -x509 -newkey rsa:2048 -sha256 -keyout ${TMPDIR}/ljw.key -out ${TMPDIR}/ljw.crt -days 5 -subj /CN=lj-warn -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/ljw.crt -key ${TMPDIR}/ljw.key -port 5448 -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} inspect -d localhost:5448 -k --lint --json 2>/dev/null | grep -q '\"warnings\"'
        RET=\$?
        kill \$PID 2>/dev/null
        exit \$RET
    "

run_test "inspect --lint --json (clean, empty array)" \
    bash -c "
        openssl req -x509 -newkey rsa:4096 -sha256 -keyout ${TMPDIR}/ljk.key -out ${TMPDIR}/ljk.crt -days 365 -subj /CN=lj-ok -nodes 2>/dev/null
        openssl s_server -cert ${TMPDIR}/ljk.crt -key ${TMPDIR}/ljk.key -port 5449 -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} inspect -d localhost:5449 -k --lint --json 2>/dev/null | grep -q '\"warnings\": \[\]'
        RET=\$?
        kill \$PID 2>/dev/null
        exit \$RET
    "

run_test "revoke certificate via pebble" \
    bash -c "
        # Issue a cert first
        ${BINARY} \
            --account-key ${KEYS_DIR}/account.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            > ${TMPDIR}/revokable.crt 2>/dev/null || exit 1
        # Revoke it (pebble CA is trusted via SSL_CERT_FILE from utils.sh)
        ${BINARY} \
            revoke --cert ${TMPDIR}/revokable.crt \
            --account-key ${KEYS_DIR}/account.key \
            --directory-url ${DIRECTORY_URL} \
            --insecure \
            > /dev/null 2>&1
    "

run_test "dump TLS certificate chain" \
    bash -c "
        openssl req -x509 -newkey rsa:2048 -keyout ${TMPDIR}/dmp.key -out ${TMPDIR}/dmp.crt -days 1 -subj /CN=dump-test -nodes 2>/dev/null
        PORT=5445
        while fuser \$PORT/tcp 2>/dev/null; do PORT=\$((PORT+1)); done
        openssl s_server -cert ${TMPDIR}/dmp.crt -key ${TMPDIR}/dmp.key -port \$PORT -tls1_2 -www 2>/dev/null &
        PID=\$!
        sleep 1
        ${BINARY} dump localhost:\$PORT -k 2>/dev/null | grep -q 'CERTIFICATE'
        RET=\$?
        kill \$PID 2>/dev/null
        exit \$RET
    "

# ==== EAB (External Account Binding) ====

run_test "Issue certificate with EAB" \
    bash -c "
        ${BINARY} \
            --account-key ${KEYS_DIR}/account_ec.key \
            --csr ${KEYS_DIR}/domain.csr \
            --acme-dir ${TMPDIR}/challenges/.well-known/acme-challenge/ \
            ${BASE_ARGS} \
            --eab-kid \"pebble-eab\" \
            --eab-hmac-key \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\" \
            > ${TMPDIR}/eab_signed.crt 2>/dev/null && \
        cert_ok ${TMPDIR}/eab_signed.crt 'Pebble'
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
