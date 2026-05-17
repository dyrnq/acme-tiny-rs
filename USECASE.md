# Use cases: certbot & acme.sh to acme-tiny-rs migration

This document maps common ACME client operations from **certbot** and **acme.sh**
to their `acme-tiny-rs` equivalents.  Where no equivalent exists, the recommended
wrapper / external tool is noted.

## 1. Obtain a certificate

| certbot                                               | acme.sh                                          | acme-tiny-rs                                                                                      |
|-------------------------------------------------------|--------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `certbot certonly --webroot -d ex.com`               | `acme.sh --issue -d ex.com -w /var/www`           | `acme-tiny-rs --account-key key --csr csr --acme-dir /var/www/.well-known/acme-challenge`       |
| `certbot certonly --standalone -d ex.com`            | `acme.sh --issue -d ex.com --standalone`          | `acme-tiny-rs --account-key key --csr csr --standalone`                                          |
| `certbot certonly --dns-cloudflare -d ex.com`        | `acme.sh --issue -d ex.com --dns dns_cf`          | `acme-tiny-rs --account-key key --csr csr --challenge-type dns-01 --dns-provider cloudflare`    |
| `certbot certonly --nginx -d ex.com`                 | n/a (acme.sh uses `--webroot` or file copy)      | ❌ N/A — acme-tiny-rs never modifies server config                                                |
| `certbot certonly --apache -d ex.com`                | n/a                                               | ❌ N/A — same as above                                                                           |

### Staging / test certificate

| certbot                | acme.sh      | acme-tiny-rs                                  |
|------------------------|--------------|-----------------------------------------------|
| `--test-cert`          | `--staging`  | `--server letsencrypt-staging`                |
| `--dry-run`            | `--staging`  | `--server letsencrypt-staging` (no dry-run flag) |

## 2. Renew a certificate

ACME has no protocol distinction between issue and renew — the same order →
authorization → challenge → finalize flow applies.  The only difference is
whether you check the existing certificate before running.

| certbot                               | acme.sh                                | acme-tiny-rs                                                                                         |
|---------------------------------------|----------------------------------------|------------------------------------------------------------------------------------------------------|
| `certbot renew` (checks expiry)       | `acme.sh --renew -d ex.com` (checks expiry) | `acme-tiny-rs --account-key key --csr csr --existing-cert old.crt --ari`                           |
| `renew_before_expiry = 30` (config)   | `Le_RenewalDays = 80` (stateful)       | `--renew-before 30` (stateless; skip if cert valid > 30 days)                                      |
| `certbot renew --force-renewal`       | `acme.sh --renew --force`             | `acme-tiny-rs --account-key key --csr csr --force` (skip ARI check)                                |
| `certbot renew --dry-run`             | `acme.sh --renew --staging`           | `--server letsencrypt-staging`                                                                      |
| cron scheduling                       | `acme.sh --cron` (pre-scheduled in acme.sh data) | System cron: `0 3 * * 0 acme-tiny-rs --account-key key --csr csr --existing-cert cert.pem --renew-before 30 --ari --output cert.pem --deploy-hook ...` |

### ARI (RFC 9773) renewal gating

| certbot                                 | acme.sh                           | acme-tiny-rs                                              |
|-----------------------------------------|-----------------------------------|-----------------------------------------------------------|
| default-on since 2.3.0                   | default-on                        | `--ari` flag (opt-in, with `--cert`)                      |
| `--no-ari` to disable                    | `NO_ARI=1` env                    | default behavior (no `--ari` flag)                        |
| `certbot ari --cert-name ex.com`         | `acme.sh --renew -d ex.com` (implicit) | `acme-tiny-rs ari --cert cert.pem` (JSON output)       |

## 3. Account management

| certbot                                           | acme.sh                                    | acme-tiny-rs                                                          |
|---------------------------------------------------|--------------------------------------------|-----------------------------------------------------------------------|
| `certbot register -m admin@ex.com --agree-tos`     | `acme.sh --register-account -m admin@ex.com` | `acme-tiny-rs --account-key key account register -m admin@ex.com`    |
| `certbot update_account -m new@ex.com`             | `acme.sh --update-account -m new@ex.com`     | `acme-tiny-rs --account-key key account update -m new@ex.com`        |
| `certbot show_account`                             | not exposed                                 | `acme-tiny-rs --account-key key account show`                        |
| `certbot unregister`                               | `acme.sh --deactivate-account`              | `acme-tiny-rs --account-key key account unregister`                  |
| key rollover (RFC 8555 §7.3.5)                     | not exposed                                 | `acme-tiny-rs --account-key old.key account change-key --new-key new.key` |

## 4. Revoke a certificate

| certbot                                         | acme.sh                                      | acme-tiny-rs                                                  |
|-------------------------------------------------|----------------------------------------------|---------------------------------------------------------------|
| `certbot revoke --cert-path cert.pem`            | `acme.sh --revoke -d ex.com`                 | `acme-tiny-rs revoke --cert cert.pem --account-key key`     |
| `certbot revoke --reason keyCompromise`          | `acme.sh --revoke -d ex.com --reason 1`      | `acme-tiny-rs revoke --cert cert.pem --account-key key --reason 1` |

## 5. Certificate inspection

| certbot                      | acme.sh                        | acme-tiny-rs                                                     |
|------------------------------|--------------------------------|------------------------------------------------------------------|
| `certbot certificates`       | `acme.sh --list`              | `acme-tiny-rs inspect -d ex.com` (TLS connection)               |
| n/a                          | `acme.sh --info -d ex.com`    | `acme-tiny-rs dump ex.com` (cert chain dump)                    |
| n/a                          | `acme.sh --show-csr csr.pem`  | `openssl req -text -in csr.pem`                                  |
| n/a                          | `acme.sh --list-ca`           | `acme-tiny-rs list-ca` (static presets)                         |
| n/a                          | n/a                            | `acme-tiny-rs inspect-ca --server letsencrypt` (directory JSON) |
| n/a                          | n/a                            | `acme-tiny-rs inspect-ca --server pebble -k` (pebble — self-signed) |

## 6. Deploy / install certificate to server

| certbot                                            | acme.sh                                                                                       | acme-tiny-rs                                                                                   |
|----------------------------------------------------|-----------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| `certbot renew --deploy-hook "nginx -s reload"`    | `acme.sh --reloadcmd "nginx -s reload"`                                                       | `--deploy-hook "nginx -s reload"`                                                              |
| auto: `--nginx` plugin copies to `/etc/nginx/ssl/` | `acme.sh --install-cert -d ex.com --key-file ... --fullchain-file ... --reloadcmd ...`        | `--output /path/fullchain.pem && --deploy-hook "cp /path/fullchain.pem /etc/nginx/ssl/; nginx -s reload"` |
| auto: certonly `--deploy-hook`                     | `--renew-hook`, `--post-hook`                                                                 | `--pre-hook`, `--post-hook`, `--renew-hook`, `--notify-hook`                                   |

## 7. DNS provider usage

| certbot                       | acme.sh                    | acme-tiny-rs                                               |
|-------------------------------|----------------------------|------------------------------------------------------------|
| `--dns-cloudflare` (plugin)   | `--dns dns_cf`             | `--challenge-type dns-01 --dns-provider cloudflare`        |
| `--dns-route53` (plugin)      | `--dns dns_aws`            | `--challenge-type dns-01 --dns-provider aws`               |
| `--dns-rfc2136` (plugin)      | `--dns dns_nsupdate`       | `--challenge-type dns-01 --dns-provider rfc2136`           |
| 15+ plugins                   | 150+ providers             | 24 providers (Aliyun, AWS, Cloudflare, DNSPod, Vercel, etc.) |

### Experimental DNS challenge types

| certbot     | acme.sh     | acme-tiny-rs                                                    |
|-------------|------------|------------------------------------------------------------------|
| n/a         | n/a         | `--challenge-type dns-persist-01` (TXT record persists, no cleanup) |
| n/a         | n/a         | `--challenge-type dns-account-01` (static DNS record per account key) |

### DNS CNAME auto-follow (challenge delegation)

| certbot          | acme.sh          | acme-tiny-rs                                 |
|------------------|------------------|----------------------------------------------|
| not supported    | not supported    | automatic (zero config, defaults on)          |

## 8. Advanced certificate features

| certbot                                              | acme.sh                                      | acme-tiny-rs                                                                        |
|------------------------------------------------------|----------------------------------------------|-------------------------------------------------------------------------------------|
| `--must-staple` (OCSP stapling extension)             | `--ocsp --must-staple`                       | ❌                                                                                   |
| `--preferred-chain "ISRG Root X1"`                    | `--preferred-chain "ISRG"`                   | ❌                                                                                   |
| `--key-type rsa/ecdsa`                                | `--keylength ec-256`                         | `openssl ecparam -genkey` (wrapper)                                                  |
| `--cert-name ex.com` (certbot's cert label)           | `-d ex.com` (implicit)                       | `--existing-cert cert.pem` (explicit path — stateless)                               |
| `--allow-subset-of-names`                             | not supported                                | ❌                                                                                   |
| `--reuse-key`                                         | `--renew --reuseKey`                         | ❌ (wrapper reuses key by not re-generating)                                          |
| IP address identifiers (RFC 8738)                     | not supported                                | ✅ (auto-detected from CSR; LE doesn't support, ZeroSSL/Google does)                |
| `--eab-kid`, `--eab-hmac-key`                         | `--eab-kid`, `--eab-hmac-key` (for ZeroSSL)  | `--eab-kid`, `--eab-hmac-key`, `--eab-hmac-alg`                                     |
| `--profile classic\|tlsserver` (ACME Profiles)        | not supported                                | `-P tlsserver` (injects `"profile"` field into new-order payload)                   |

## 9. External Account Binding (EAB)

| certbot                                          | acme.sh                                          | acme-tiny-rs                                                             |
|--------------------------------------------------|--------------------------------------------------|--------------------------------------------------------------------------|
| `--eab-kid`, `--eab-hmac-key` (config file)       | `--eab-kid`, `--eab-hmac-key`                    | `--eab-kid`, `--eab-hmac-key`, `--eab-hmac-alg HS256\|HS384\|HS512`         |
| No algorithm selection                           | No algorithm selection                           | HS256 (default), HS384, HS512                                             |

## 10. Port and timeout control

| certbot                       | acme.sh                       | acme-tiny-rs                                                                       |
|-------------------------------|-------------------------------|------------------------------------------------------------------------------------|
| `--http-01-port 8080`         | `--httpport 8080`             | port 80 only (ACME spec requires port 80)                                          |
| `--tls-alpn-01-port 4443`     | not supported                 | `--challenge-type tls-alpn-01` (port 443, ACME spec)                               |
| `--issuance-timeout 90`       | not supported                 | `--connect-timeout 10`, `--timeout 30` (optional, system defaults if unset)        |

## 11. Proxy support

All tools respect the standard proxy environment variables:

| certbot                                              | acme.sh                                              | acme-tiny-rs                                              |
|------------------------------------------------------|------------------------------------------------------|-----------------------------------------------------------|
| `HTTP_PROXY=http://proxy:8080 certbot ...`            | `HTTP_PROXY=http://proxy:8080 acme.sh ...`            | `HTTPS_PROXY=http://proxy:8118 acme-tiny-rs ...`         |

## 12. Output format / scripting

| certbot                                           | acme.sh                                     | acme-tiny-rs                                                            |
|---------------------------------------------------|---------------------------------------------|-------------------------------------------------------------------------|
| cert stored in `/etc/letsencrypt/live/`            | cert stored in `~/.acme.sh/domain/`          | `--output /path/cert.pem` (atomic: tmp → rename) or stdout              |
| JSON output: `certbot certificates --json`         | n/a                                         | `list-ca --json`, `inspect --json`, `inspect-ca` (raw JSON)             |
| `--quiet` flag                                     | `--debug 0\|1\|2\|3`                          | `-v`, `-vv`, `-vvv` (stderr verbosity)                                  |

## 13. Key and cert utilities

| certbot     | acme.sh                          | acme-tiny-rs                                                           |
|-------------|----------------------------------|------------------------------------------------------------------------|
| n/a         | `--to-pkcs8`                     | `openssl pkey` (wrapper)                                               |
| n/a         | `--to-pkcs12`                    | `openssl pkcs12 -export` (wrapper)                                     |
| n/a         | n/a                              | `acme-tiny-rs thumbprint --account-key key` (JWK thumbprint for stateless HTTP-01) |

## 14. Binary size

| Tool            | Size                                | Notes                                                   |
|-----------------|-------------------------------------|---------------------------------------------------------|
| certbot         | ~5 MB + Python runtime (~50 MB)     | `apt install certbot`                                    |
| acme.sh         | ~500 KB shell script                | requires openssl + curl (~2 MB)                         |
| acme-tiny-rs    | **~3.4 MB**                         | static binary, zero runtime dependencies, runs on any Linux kernel |

## 15. Integration tests

| Tool            | Count     | Framework                                  |
|-----------------|-----------|--------------------------------------------|
| certbot         | ~2000+    | pytest + certbot-ci                        |
| acme.sh         | ~200      | bash + Let's Encrypt staging               |
| acme-tiny-rs    | **58**    | bash + Pebble ACME test server             |

## Design philosophy differences

| Aspect            | certbot                                         | acme.sh                                             | acme-tiny-rs                                                       |
|-------------------|-------------------------------------------------|-----------------------------------------------------|--------------------------------------------------------------------|
| State             | Stateful (config DB, cert lineage)              | Stateful (`.acme.sh/domain/` dir)                   | **Stateless** (user controls paths)                                |
| Server config     | Parses nginx/apache config                      | File copy + reloadcmd                               | File copy + reloadcmd                                              |
| Cron              | auto-installs systemd timer / cron               | `--cron` subcommand (pre-scheduled)                 | user manages cron (one-liner)                                      |
| Key generation    | `--key-type rsa\|ecdsa`                          | `--keylength ec-256` account/domain                 | `openssl ecparam -genkey` (wrapper)                                |
| CSR creation      | auto-generates                                  | auto-generates from `-d`                            | user provides CSR                                                  |
| CA discovery      | compiled-in LE + staging                        | compiled-in LE + ZeroSSL + Buypass                  | `list-ca` (12 presets), `inspect-ca` (dynamic)                     |
