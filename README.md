# acme-tiny-rs

A Rust port of [acme-tiny](https://github.com/diafygi/acme-tiny), fully compatible with its CLI and ACME workflow.

## Relationship to acme-tiny

`acme-tiny-rs` is a feature-equivalent Rust implementation of `acme-tiny` (Python):

| Aspect          | acme-tiny (Python)                          | acme-tiny-rs (Rust)                                    |
| :-------------- | :------------------------------------------ | :----------------------------------------------------- |
| Language        | Python 2/3                                  | Rust                                                   |
| Dependencies    | Python + OpenSSL CLI                        | Zero runtime dependencies (static linking)             |
| Startup time    | ~50ms interpreter                           | < 1ms                                                  |
| Binary size     | Requires Python runtime                     | ~2.7MB single file                                     |
| Key parsing     | `openssl rsa` / `openssl req` subprocess    | Pure Rust (`rsa` / `p256` / `p384` / `x509-parser`)    |
| HTTP/TLS        | `urllib` + system CA                        | `reqwest` + `rustls` (bundled root certs)              |
| Cross-platform  | Requires Python + OpenSSL install           | Single binary, no runtime deps                         |

## Advantages

- **Single-file deployment**: `scp` one binary to your server — no Python or OpenSSL needed
- **Key types**: RSA + ECDSA P-256/P-384 + Ed25519 account keys (auto-detected from PEM)
  - **⚠️ Let's Encrypt does not support Ed25519 certificates** — Ed25519 works for *account keys* only (JWS signing). Domain keys for CSR signing must use RSA or ECDSA P-256/P-384. P-521 support deferred (upstream crate pre-release).
- **Statically linked**: `x86_64-unknown-linux-musl` builds have zero `.so` dependencies — runs on any Linux kernel
- **Drop-in compatible**: CLI arguments match `acme-tiny` exactly

## Installation

### Prebuilt binaries

Download the appropriate binary from [Releases](https://github.com/dyrnq/acme-tiny-rs/releases):

```sh
VER=$(curl -s https://api.github.com/repos/dyrnq/acme-tiny-rs/releases/latest | grep tag_name | cut -d'"' -f4) && \
curl -L -o acme-tiny-rs "https://github.com/dyrnq/acme-tiny-rs/releases/download/${VER}/acme-tiny-rs-${VER}-x86_64-unknown-linux-musl"
chmod +x acme-tiny-rs
```

### Build from source

```sh
git clone https://github.com/dyrnq/acme-tiny-rs.git
cd acme-tiny-rs
cargo build --release
# binary at ./target/release/acme-tiny-rs
```

Static build (musl):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Usage

### 1. Create a Let's Encrypt account private key

```sh
# RSA
openssl genrsa 4096 > account.key

# ECDSA P-256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 > account.key

# ECDSA P-384
openssl ecparam -genkey -name secp384r1 > account.key
```

### 2. Create a CSR

```sh
# Generate a domain private key
openssl genrsa 4096 > domain.key

# Single domain
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr

# Multiple domains
openssl req -new -sha256 -key domain.key -subj "/" \
    -addext "subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com" > domain.csr

# Multiple domains (openssl < 1.1.1)
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) \
    > domain.csr
```

### 3. Set up challenge directory

```sh
mkdir -p /var/www/challenges/
```

```nginx
# nginx example
server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }
}
```

### 4. Get a signed certificate

```sh
acme-tiny-rs \
    --account-key ./account.key \
    --csr ./domain.csr \
    --acme-dir /var/www/challenges/ \
    > signed_chain.crt
```

Staging environment (test):

```sh
acme-tiny-rs \
    --account-key ./account.key \
    --csr ./domain.csr \
    --acme-dir /var/www/challenges/ \
    --directory-url https://acme-staging-v02.api.letsencrypt.org/directory \
    > signed_chain.crt
```

### 5. Install the certificate

```nginx
server {
    listen 443 ssl;
    server_name yoursite.com www.yoursite.com;

    ssl_certificate /path/to/signed_chain.crt;
    ssl_certificate_key /path/to/domain.key;
}
```

### 6. Auto-renewal cron job

```sh
#!/bin/sh
# renew_cert.sh
acme-tiny-rs \
    --account-key /path/to/account.key \
    --csr /path/to/domain.csr \
    --acme-dir /var/www/challenges/ \
    > /path/to/signed_chain.crt.tmp \
    || exit
mv /path/to/signed_chain.crt.tmp /path/to/signed_chain.crt
service nginx reload
```

```sh
# crontab (runs once per month)
0 0 1 * * /path/to/renew_cert.sh 2>> /var/log/acme_tiny.log
```

## CLI Reference

```
--account-key <PATH>       Path to account private key (RSA or ECDSA P-256/P-384)
--csr <PATH>               Path to CSR file
--acme-dir <PATH>          Path to .well-known/acme-challenge/ directory (http-01)
--quiet                    Suppress output except for errors
--disable-check            Skip self-check of challenge file (http-01)
--directory-url <URL>      CA directory URL [default: Let's Encrypt production]
--ca <URL>                 DEPRECATED, use --directory-url instead
--contact <CONTACT>...     Contact details (e.g. mailto:admin@example.com)
--check-port <PORT>        Port for http-01 self-check [default: 80]
--challenge-type <TYPE>    http-01 (default), dns-01, or dns-persist-01
--dns-provider <NAME>      DNS provider for DNS challenges [default: manual]
--agree-tos                Agree to CA Terms of Service [default: true]
--eab-kid <KID>            EAB Key Identifier for CAs requiring EAB
--eab-hmac-key <KEY>       EAB HMAC Key (base64url-encoded)
--pre-hook <CMD>           Command/script to run before certificate issuance
--post-hook <CMD>          Command/script to run after issuance (success or failure)
--renew-hook <CMD>         Command/script to run after successful renewal
--deploy-hook <CMD>        Command/script to run to deploy the certificate
--notify-hook <CMD>        Command/script to run for notifications
--ca-bundle <PATH>         Additional CA certificate bundle for TLS verification
```

See [DNS.md](DNS.md) for all 24 supported DNS providers.

## License

MIT — same as acme-tiny.
