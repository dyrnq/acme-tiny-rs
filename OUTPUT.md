# Stdout vs `--output` and shell redirection pitfalls

This document explains how `acme-tiny-rs` handles certificate output, and
why `--output` is preferred over shell redirection (`>` or `1>`) —
especially when combining renewal gating flags like `--ari` and `--renew-before`.

## The problem: shell `>` truncates before the command runs

```sh
# BAD — will destroy your certificate even if issuance is skipped!
acme-tiny-rs --renew-before 30 --cert /etc/ssl/cert.pem > /etc/ssl/cert.pem
```

The shell processes `>` **before** launching `acme-tiny-rs`.  It truncates
`/etc/ssl/cert.pem` to zero bytes, then runs the command.  Even if `--renew-before`
decides "certificate is still valid, skip issuance", the cert file is
already gone — replaced by an empty file.

## The fix: use `--output`

```sh
# GOOD — --output is only written on successful issuance
acme-tiny-rs --renew-before 30 --cert /etc/ssl/cert.pem \
    --output /etc/ssl/cert.pem
```

| Scenario | `> stdout` | `--output` |
|----------|-----------|-----------|
| Issuance succeeds | ✅ cert written | ✅ cert written (atomic: tmp→rename) |
| `--renew-before` skip | ❌ **file truncated to empty** | ✅ file untouched |
| `--ari` skip (not in window) | ❌ **file truncated to empty** | ✅ file untouched |
| Crash mid-write | ❌ half-written cert | ✅ tmp file, no rename |

## Why this matters now

Before v0.1.6, `acme-tiny-rs` always issued a certificate on every run.
Shell `>` was safe because output was guaranteed:

```sh
# Pre-v0.1.6: safe because no skip mechanism existed
acme-tiny-rs --account-key key --csr csr > /etc/ssl/cert.pem
```

After v0.1.6, with `--renew-before` and `--ari`, issuance may be **intentionally
skipped**.  The command exits successfully but produces no output.
Shell `>` turns this into data loss.

## Atomic output guarantee

When `--output /path/cert.pem` is used, the write is **atomic**:

1. Write certificate to `/path/cert.pem.tmp-<PID>`
2. `rename()` the temp file to `/path/cert.pem`

If the process crashes between step 1 and 2, the original file remains
intact — only the temp file is left behind (cleanup on next run).

When `--output` is specified and issuance is skipped (`--renew-before` / `--ari`
gate), no file is written at all — the `certificate.is_empty()` guard
returns early before the output block.

## Recommendations

1. **Always use `--output`** when the output path matters (production certs,
   files read by nginx/apache, paths monitored by `inotify`).

2. **If you must use `>`**, write to a temp location first, then move:

   ```sh
   acme-tiny-rs --account-key key --csr csr > /tmp/cert.tmp \
       && mv /tmp/cert.tmp /etc/ssl/cert.pem
   ```

3. **Cron example:**

   ```sh
   0 3 * * 0 acme-tiny-rs --account-key key --csr csr \
       --cert /etc/ssl/cert.pem --renew-before 30 --ari \
       --output /etc/ssl/cert.pem \
       --deploy-hook "systemctl reload nginx"
   ```
