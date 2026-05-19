# ACME Renewal Information (ARI) support

acme-tiny-rs implements [RFC 9773][rfc9773] ARI — the ACME Renewal Information
extension — to avoid unnecessary certificate issuance.

## CLI flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--existing-cert` / `--cert` | `Option<String>` | — | Path to existing certificate for ARI check + `replaces` field |
| `--ari` | `bool` | `false` | Query ARI endpoint before issuance; skip if not in renewal window |
| `--force` | `bool` | `true` | Force issuance, skip ARI check. Default `true` for backward compatibility |
| `--output` / `-o` | `Option<String>` | `stdout` | Output path (atomic write: temp file → rename) |

## Behavior matrix

| `--ari` | `--existing-cert` | `--force` | Behavior |
|---------|-------------------|-----------|----------|
| ✗ | ✗ | — | **Original behavior** — always issue |
| ✓ | ✗ | — | Warn, proceed (no cert to query) |
| ✓ | ✓ | — | Query ARI window from `--existing-cert`. Skip if not in window. Pass `replaces` to new-order if proceeding |
| ✗ | ✓ | — | Compute certID, pass `replaces` to new-order. No ARI window check |

### Priority

`--ari` overrides `--force` — if `--ari` is set and ARI says "not in window", the tool
exits early **without running hooks or writing output**, regardless of `--force`.

[//]: # (footnote: --force is always true by default; setting it to false is not
currently possible, preserving original acme-tiny behavior.)

## Use case matrix

| # | `--ari` | `--cert` | `--force` | `--output` | Behavior |
|---|---------|----------|-----------|------------|----------|
| 1 | ✗ | ✗ | — | ✗ | Original: always issue, stdout |
| 2 | ✗ | ✗ | — | `/path` | Original: always issue, write to file |
| 3 | ✗ | ✓ | — | ✗ | Issue with `replaces`, stdout |
| 4 | ✗ | ✓ | — | `/path` | Issue with `replaces`, write to file |
| 5 | ✓ | ✗ | — | — | Warn "no --cert", proceed anyway |
| 6 | ✓ | ✓ | — | ✗ | Query ARI. **In window** → issue with `replaces`, stdout. **Not in window** → exit, stdout empty |
| 7 | ✓ | ✓ | — | `/path` | Query ARI. **In window** → issue with `replaces`, atomic write. **Not in window** → exit, `--output` **NOT written** (file unchanged) |
| 8 | ✓ | ✓ | ✓ | — | Same as #6/#7 — `--ari` wins over `--force` |
| 9 | ✗ | ✓ | — | — | `--renew-before N`: skip if cert valid > N days (certbot: `renew_before_expiry`, acme.sh: `Le_RenewalDays`) |
| 10 | ✗ | ✓ | ✓ | — | `--renew-before N --force`: force overrides the gate, always issue |

### Key guarantees

- **`--output` preserved on ARI/renew-before skip:** when the expiry gate or ARI
  says not in window, the output file is never touched — the existing certificate
  remains intact. Internally,
  `get_crt()` returns an empty string and the output block is skipped entirely.
- **`replaces` sent when `--cert` provided:** regardless of `--ari`, the
  certificate ID is computed and passed as the `"replaces"` field in the
  new-order payload (RFC 8739 rate-limit exemption).
- **Hooks not executed on ARI/renew-before skip:** all hooks (pre, post, deploy, renew) are
  guarded by the empty-certificate check and do not run when issuance is skipped.

## Renewal flow

```sh
# Cron / manual renewal with ARI:
acme-tiny-rs --account-key account.key --csr domain.csr \
    --existing-cert /etc/ssl/domain.crt --ari \
    --output /etc/ssl/domain.crt.new
# → if not in window: exits silently (no hooks, no file write)
# → if in window: issues cert, atomic write to output, runs hooks
```

## Atomic output

When `--output` is set, the certificate is written to a temp file
(`<path>.tmp-<pid>`) then atomically renamed to the target path.  This prevents
web servers from reading a half-written certificate file if the process
crashes mid-write.

## ARI subcommand

For manual ARI inspection:

```sh
acme-tiny-rs ari --cert /etc/ssl/domain.crt
# → {"suggestedWindow":{"start":"...","end":"..."},...}
```

## Integration with hooks

When ARI causes early exit (not in window):
- **pre-hook**: NOT executed
- **deploy-hook**: NOT executed
- **post-hook**: NOT executed
- **renew-hook**: NOT executed

This matches certbot and acme.sh behavior — hooks are tied to successful
certificate operations, not to skipped checks.

## ARI subcommand vs `--ari` flag

acme-tiny-rs provides **two interfaces** to ARI — choose based on your use case:

| | `ari` subcommand | `--ari` flag (main flow) |
|---|---|---|
| **Purpose** | Manual inspection | Automated renewal gating |
| **Invocation** | `acme-tiny-rs ari --cert cert.crt` | `acme-tiny-rs --ari --existing-cert cert.crt ...` |
| **Output** | Raw JSON from renewalInfo endpoint | Silently exits or proceeds |
| **Affects issuance** | ❌ No | ✅ Yes — skips or proceeds |
| **Affects hooks** | ❌ No | ✅ Yes — hooks skipped if not in window |
| **Affects `--output`** | ❌ No | ✅ Yes — no file written if skipped |
| **Stdin support** | ✅ `--cert -` | ✅ `--existing-cert -` |
| **Verbose** | ✅ `-v`, `-vv`, `-vvv` | ✅ stderr via `--verbose` |

### Manual inspection (`ari` subcommand)

Use for one-off checks, debugging, or scripting:

```sh
# Check if a cert is in renewal window
acme-tiny-rs ari --cert /etc/ssl/domain.crt
# → {"suggestedWindow":{"start":"2026-07-13T00:00:00Z","end":"2026-07-15T00:00:00Z"}}

# Pipe from remote server
ssh server cat /etc/ssl/domain.crt | acme-tiny-rs ari --cert -

# Verbose mode for debugging
acme-tiny-rs ari --cert domain.crt -vvv
# → [ari] certID = AbCdEf.XyZ123
# → [ari] GET https://...
# → [ari] Response: HTTP 200 OK
```

### Automated gating (`--ari` flag)

Use in cron / renewal scripts to skip unnecessary issuance:

```sh
# In cron: only re-issue if CA says it's time
acme-tiny-rs --account-key key --csr csr \
    --existing-cert /etc/ssl/domain.crt --ari \
    --output /etc/ssl/domain.crt \
    --deploy-hook "systemctl reload nginx"

# With --force (default): always issue, ignoring ARI
acme-tiny-rs --account-key key --csr csr ...

# With --ari but no --existing-cert: warns, proceeds anyway
acme-tiny-rs --account-key key --csr csr --ari ...
```

## References

- [RFC 9773 — ACME Renewal Information][rfc9773]
- [Let's Encrypt ARI Integration Guide](https://letsencrypt.org/2024/04/25/guide-to-integrating-ari-into-existing-acme-clients)
- [draft-ietf-acme-ari-03](https://datatracker.ietf.org/doc/draft-ietf-acme-ari-03/)

[rfc9773]: https://www.rfc-editor.org/rfc/rfc9773.html

## alreadyReplaced (HTTP 409)

When a `replaces` order targets a certificate already replaced by another process,
the CA returns `urn:ietf:params:acme:error:alreadyReplaced` (HTTP 409). acme-tiny-rs
auto-retries the newOrder request **without** the `replaces` field — matching acme.sh
and lego behavior. This ensures concurrent renewals (e.g., two cron jobs racing on
the same certificate) don't trigger a permanent failure.
