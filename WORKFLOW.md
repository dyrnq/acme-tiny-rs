# Usage patterns

| Scenario                         | Command                                                                                                         |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Always issue (no gate)           | `--account-key key --csr csr --acme-dir /var/www/...`                                                           |
| Issue with `replaces`            | `--account-key key --csr csr --cert old.crt ...`                                                                |
| ARI gate: skip if not in window  | `--account-key key --csr csr --cert old.crt --ari ...`                                                          |
| Days gate: skip if >30 days left | `--account-key key --csr csr --cert old.crt --renew-before 30 ...`                                              |
| Cron-safe output (atomic)        | `... --output cert.pem`                                                                                         |
| Short-lived profile (6-day cert) | `... -P shortlived`                                                                                             |
| DNS CNAME alias override         | `--account-key key --csr csr --challenge-type dns-01 --dns-provider cloudflare --challenge-alias alias.com ...` |
| DNS challenge (provider)         | `--account-key key --csr csr --challenge-type dns-01 --dns-provider cloudflare ...`                             |
| DNS persist (no cleanup)         | `--account-key key --csr csr --challenge-type dns-persist-01 --dns-provider cloudflare ...`                     |
| DNS account (per-account)        | `--account-key key --csr csr --challenge-type dns-account-01 --dns-provider cloudflare ...`                     |
| Standalone HTTP server           | `--account-key key --csr csr --standalone ...`                                                                  |
| Standalone TLS-ALPN server       | `--account-key key --csr csr --challenge-type tls-alpn-01 ...`                                                  |
| Hooks (deploy/renew/post)        | `... --deploy-hook "nginx -s reload"`                                                                           |
| EAB (External Account Binding)   | `... --eab-kid KID --eab-hmac-key KEY`                                                                          |
| alreadyReplaced → retry          | CA returns `alreadyReplaced` → retry order without `replaces`                                             |

### Gate behavior

When `--renew-before` or `--ari` is set, the gate applies regardless of `--force` default:

```sh
# These are equivalent — gate always active
... --cert old.crt --renew-before 30
... --cert old.crt --renew-before 30 --force
```

## Full lifecycle

```
                    ┌─────────────────────────┐
                    │    Parse keys + CSR     │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │      Renewal gate        │
                    │  ┌────────┐ ┌────────┐  │
                    │  │  Days  │ │  ARI   │  │ ← mutually exclusive
                    │  └───┬────┘ └───┬────┘  │
                    └──────┼─────┬─────┼──────┘
                      skip │     │     │ skip
                    ┌──────▼──┐  │  ┌──▼──────┐
                    │   exit   │  │  │   exit  │
                    │ (empty)  │  │  │ (empty) │
                    └─────────┘  │  └─────────┘
                                 │
                                 │ proceed
                    ┌────────────▼─────────────┐
                    │       ACME order          │
                    │  (with replaces if --cert)│
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   Challenge validation    │
                    │  http-01 / dns-01 /       │
                    │  dns-persist-01 /         │
                    │  dns-account-01           │
                    │  tls-alpn-01              │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │  Finalize + download cert │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   --output (atomic)       │
                    │   or stdout               │
                    └──────────────────────────┘
```

## ACME error types (RFC 8555)

| #  | Error Type                     | HTTP | Recoverable? | Handling                        |
| -- | ------------------------------ | ---- | ------------ | ------------------------------- |
| 1  | `serverInternal`               | 500  | No           | bail!                           |
| 2  | `malformed`                    | 400  | No           | bail!                           |
| 3  | `badNonce`                     | 400  | **Yes**      | retry (max 100, fresh nonce)    |
| 4  | `badCSR`                       | 400  | No           | bail!                           |
| 5  | `userActionRequired`           | 403  | Automatic    | `--agree-tos` handles           |
| 6  | `externalAccountRequired`      | 403  | No           | bail! (re-run with --eab-*)    |
| 7  | `connection`                   | 400  | No           | bail! (CA can't reach domain)   |
| 8  | `unauthorized`                 | 403  | No           | bail!                           |
| 9  | `invalidContact`               | 400  | No           | bail!                           |
| 10 | `invalidProfile`               | 400  | No           | bail!                           |
| 11 | `unsupportedContact`           | 400  | No           | bail!                           |
| 12 | `accountDoesNotExist`          | 400  | No           | bail!                           |
| 13 | `badRevocationReason`          | 400  | No           | bail!                           |
| 14 | `alreadyRevoked`               | 400  | No           | bail!                           |
| 15 | `orderNotReady`                | 403  | No           | bail!                           |
| 16 | `badPublicKey`                 | 400  | No           | bail!                           |
| 17 | `badSignatureAlgorithm`        | 400  | No           | bail!                           |
| 18 | `alreadyReplaced`              | 409  | **Yes**      | retry without `replaces` field  |
