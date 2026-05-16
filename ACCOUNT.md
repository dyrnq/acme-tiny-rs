# Account subcommand

`acme-tiny-rs account` manages the lifecycle of an ACME account — register,
inspect, update contact information, and deactivate.

## Quick reference

```sh
acme-tiny-rs --account-key key account register -m admin@example.com
acme-tiny-rs --account-key key account show
acme-tiny-rs --account-key key account update -m new@example.com
acme-tiny-rs --account-key key account unregister
```

Short form: `acme-tiny-rs a show`, `acme-tiny-rs a register`, etc.

## Subcommands

| Command | Description | ACME endpoint |
|---------|-------------|---------------|
| `register` | Create a new ACME account | POST `newAccount` |
| `show` | Display account details (status, contact, orders URL) | POST account URL |
| `update` | Update account contact email(s) | POST account URL |
| `unregister` | Deactivate the account (irreversible) | POST account URL with `{"status":"deactivated"}` |
| `change-key` | Roll over to a new account key (RFC 8555 §7.3.5) | POST account URL with `{"keyChange":<inner JWS>}` |

## Flags

### Account-level flags (apply to all subcommands)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server` | `String` | `letsencrypt` | CA preset name or full directory URL |
| `--directory-url` | `Option<String>` | — | Override the directory URL directly |
| `-k`, `--insecure` | `bool` | `false` | Skip TLS certificate verification (Pebble/testing) |
| `-v`, `-vv`, `-vvv` | `Count` | — | Verbose: `-v` = server URL, `-vv` = HTTP request URLs |

These flags use clap `global = true` so they are accepted after the sub-subcommand:

```sh
acme-tiny-rs --account-key key account register --server pebble -k -v
```

### `register` flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-m`, `--email` | `Vec<String>` | — | Contact email(s) for the account |
| `--agree-tos` | `bool` | `true` | Agree to the CA's Terms of Service |
| `--eab-kid` | `Option<String>` | — | EAB Key Identifier (for CAs requiring EAB) |
| `--eab-hmac-key` | `Option<String>` | — | EAB HMAC Key (base64url-encoded) |
| `--eab-hmac-alg` | `String` | `HS256` | HMAC algorithm: `HS256`, `HS384`, or `HS512` |

### `update` flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-m`, `--email` | `Vec<String>` | — | New contact email(s) |

## Key handling

`--account-key` is on the **parent CLI** (before the subcommand name), not on `account`
itself.  This avoids clap flag conflicts and lets the same key be used across all
account operations:

```sh
# Correct: --account-key before the subcommand
acme-tiny-rs --account-key account.key account show --server letsencrypt

# Wrong: --account-key after the subcommand
acme-tiny-rs account show --account-key account.key --server letsencrypt
# → error: unexpected argument '--account-key' found
```

Any valid ACME account key format works: RSA (PKCS#1 or PKCS#8 PEM), ECDSA P-256,
or ECDSA P-384.

## Account lookup (KID resolution)

All subcommands (`show`, `update`, `unregister`) first resolve the account's KID
(Key Identifier — the account URL) by POSTing a minimal `newAccount` request
(`{"termsOfServiceAgreed": true}`) with the provided key.  If the account already
exists, the CA returns `200 OK` with a `Location` header pointing to the account
URL.  If the account does not exist, the command errors out — use `register` first.

## External Account Binding (EAB)

`register` supports EAB (RFC 8555 §7.3.4) for CAs that require it (ZeroSSL,
Google Trust Services, Pebble with EAB enabled).  Pass all three EAB flags:

```sh
acme-tiny-rs --account-key key account register \
    --eab-kid "your-kid" \
    --eab-hmac-key "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" \
    --eab-hmac-alg HS256
```

The EAB JWS is computed from:
- `protected`: `{"alg":"<alg>","kid":<eab-kid>,"url":<newAccount URL>}`
- `payload`: base64url of the account key JWK
- `signature`: HMAC over `protected.payload` using the decoded EAB HMAC key

## Examples

### Register a new account

```sh
acme-tiny-rs --account-key account.key account register -m admin@example.com
# → Account URL: https://acme-v02.api.letsencrypt.org/acme/acct/123456789
# → {"status":"valid","contact":["mailto:admin@example.com"],...}
```

### Show account details

```sh
acme-tiny-rs --account-key account.key account show
# → {"status":"valid","contact":["mailto:admin@example.com"],"orders":"..."}
```

### Update contact email

```sh
acme-tiny-rs --account-key account.key account update -m new-admin@example.com
# → {"status":"valid","contact":["mailto:new-admin@example.com"],...}
```

### Deactivate account

```sh
acme-tiny-rs --account-key account.key account unregister
# → {"status":"deactivated",...}
# Note: this is irreversible.  The CA may allow re-registration with
# the same key, but this is not guaranteed across all CAs.
```

### Change account key (key rollover)

```sh
acme-tiny-rs --account-key old.key account change-key --new-key new.key
# → {"status":"valid",...}
# The account is now controlled by new.key; old.key is no longer valid.
```

### Register with EAB (ZeroSSL)

```sh
acme-tiny-rs --account-key account.key account register \
    --server zerossl \
    --eab-kid "eab-key-id" \
    --eab-hmac-key "base64url-encoded-hmac-key" \
    --eab-hmac-alg HS256 \
    -m admin@example.com
```

### Pebble debugging with verbose output

```sh
acme-tiny-rs --account-key account.key account show \
    --server pebble -k -vvv
# → [account] Server: https://localhost:14000/dir
# → [account] GET https://localhost:14000/my-account/abc123
# → {"status":"valid",...}
```

## Integration with the main flow

The `account` subcommand is **independent** from the certificate issuance flow.
You can register/manage accounts without a CSR, and you can issue certificates
without explicitly calling `account register` — the main flow auto-registers on
first use.

| Operation | Main flow (`get_crt`) | Account subcommand |
|-----------|----------------------|-------------------|
| Register | Automatic on first run | `account register` |
| Show details | Not exposed | `account show` |
| Update contact | Not exposed | `account update` |
| Deactivate | Not exposed | `account unregister` |

## Implementation

- `src/commands/account.rs` — ~80 lines, standalone async functions
- Reuses `send_signed_request` from main JWS signing path — zero new dependencies
- KID resolution: lightweight `newAccount` POST to get account URL from Location header
- Passes `--server`/`--directory-url`/`-k` via clap `global = true` flags
- Verbose output: `-v` prints server URL, `-vv` prints each HTTP request URL

## References

- [RFC 8555 §7.3 — Account Management](https://www.rfc-editor.org/rfc/rfc8555#section-7.3)
- [RFC 8555 §7.3.4 — External Account Binding](https://www.rfc-editor.org/rfc/rfc8555#section-7.3.4)
- [EAB.md](EAB.md) — External Account Binding details
