#!/usr/bin/env bash
# Install Pebble ACME test server
set -euo pipefail

PEBBLE_VERSION="${1:-latest}"
PEBBLE_DIR="${PEBBLE_DIR:-/opt/pebble}"
PEBBLE_CERT_DIR="${PEBBLE_DIR}/certs"

echo "=== Installing Pebble ACME test server ==="

mkdir -p "${PEBBLE_DIR}" "${PEBBLE_CERT_DIR}"

# Download pebble binary
if [ "${PEBBLE_VERSION}" = "latest" ]; then
    PEBBLE_PATH="releases/latest/download/pebble-linux-amd64.tar.gz"
else
    PEBBLE_PATH="releases/download/${PEBBLE_VERSION}/pebble-linux-amd64.tar.gz"
fi

PEBBLE_URL="https://github.com/letsencrypt/pebble/${PEBBLE_PATH}"
PEBBLE_MIRROR="https://files.m.daocloud.io/github.com/letsencrypt/pebble/${PEBBLE_PATH}"

echo "Downloading pebble..."
if ! curl -fsSL --connect-timeout 10 "${PEBBLE_MIRROR}" -o /tmp/pebble.tar.gz 2>/dev/null; then
    echo "  mirror failed, trying direct download..."
    curl -fsSL "${PEBBLE_URL}" -o /tmp/pebble.tar.gz
fi
tar -xzf /tmp/pebble.tar.gz -C /tmp
# Find the pebble binary in extracted tree
PEBBLE_BIN=$(find /tmp -name pebble -type f 2>/dev/null | head -1)
if [ -z "${PEBBLE_BIN}" ]; then
    echo "ERROR: pebble binary not found in archive"
    exit 1
fi
cp "${PEBBLE_BIN}" "${PEBBLE_DIR}/pebble"
chmod 755 "${PEBBLE_DIR}/pebble"
rm -f /tmp/pebble.tar.gz

# Generate test certificates for pebble (same as acme-tiny test certs)
echo "Generating pebble TLS certificates..."
openssl genrsa -out "${PEBBLE_CERT_DIR}/pebble.key" 4096 2>/dev/null
openssl req -x509 -new -nodes \
    -key "${PEBBLE_CERT_DIR}/pebble.key" \
    -days 9999 \
    -subj "/" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectAltName=DNS:localhost,DNS:pebble" \
    -out "${PEBBLE_CERT_DIR}/pebble.crt" 2>/dev/null

# Create default pebble config
cat > "${PEBBLE_DIR}/pebble-config.json" << EOF
{
    "pebble": {
        "listenAddress": "127.0.0.1:14000",
        "managementListenAddress": "127.0.0.1:15000",
        "certificate": "${PEBBLE_CERT_DIR}/pebble.crt",
        "privateKey": "${PEBBLE_CERT_DIR}/pebble.key",
        "httpPort": 5002,
        "tlsPort": 5001,
        "ocspResponderURL": "",
        "externalAccountBindingRequired": false
    }
}
EOF

echo "Pebble installed: ${PEBBLE_DIR}/pebble"
echo "Config: ${PEBBLE_DIR}/pebble-config.json"

# Ensure files are readable by the user running tests (not just root)
chmod -R a+rX "${PEBBLE_DIR}"

"${PEBBLE_DIR}/pebble" -h 2>&1 | head -1 || true
echo "=== Pebble installation complete ==="
