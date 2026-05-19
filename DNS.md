# DNS-01 Challenge

acme-tiny-rs supports [RFC 8555 §8.4](https://www.rfc-editor.org/rfc/rfc8555#section-8.4) DNS-01 challenges via native Rust DNS provider plugins.

## How DNS-01 works

```
1. ACME server issues a challenge token
2. Client computes: key_auth = token + "." + base64url(SHA-256(canonical JWK))
3. Client computes: txt_value = base64url(SHA-256(key_auth))
4. Client creates TXT record: _acme-challenge.{domain} = {txt_value}
5. ACME server validates by querying DNS
6. Client removes TXT record after validation
```

## Usage

```sh
# Manual DNS (prompts you to set the TXT record)
acme-tiny-rs --account-key account.key --csr domain.csr \
    --challenge-type dns-01

# Cloudflare (reads CF_API_TOKEN from env)
acme-tiny-rs --account-key account.key --csr domain.csr \
    --challenge-type dns-01 --dns-provider cloudflare

# Alibaba Cloud
acme-tiny-rs --account-key account.key --csr domain.csr \
    --challenge-type dns-01 --dns-provider alibaba
```

## CLI Options

| Option                  | Description                        |
| :---------------------- | :--------------------------------- |
| `--challenge-type`      | `http-01` (default) or `dns-01`    |
| `--dns-provider <NAME>` | DNS provider name, see table below |

## Supported Providers

| Provider       | `--dns-provider`                 | Required Env Vars                                                                                         | Category        |
| :------------- | :------------------------------- | :-------------------------------------------------------------------------------------------------------- | :-------------- |
| Cloudflare     | `cloudflare` / `cf`              | `CF_API_TOKEN` or `CF_API_KEY` + `CF_API_EMAIL`                                                           | Domain Registrar|
| GoDaddy        | `godaddy` / `gd`                 | `GD_Key`, `GD_Secret`                                                                                     | Domain Registrar|
| Namecheap      | `namecheap`                      | `NAMECHEAP_API_KEY`, `NAMECHEAP_USERNAME`                                                                 | Domain Registrar|
| NameSilo       | `namesilo`                       | `NAMESILO_API_KEY`                                                                                        | Domain Registrar|
| Porkbun        | `porkbun`                        | `PORKBUN_API_KEY`, `PORKBUN_SECRET_API_KEY`                                                               | Domain Registrar|
| Gandi          | `gandi`                          | `GANDI_LIVEDNS_KEY`                                                                                       | Domain Registrar|
| Alibaba Cloud  | `alibaba` / `ali`                | `Ali_Key`, `Ali_Secret`                                                                                   | Cloud           |
| Tencent Cloud  | `tencent` / `tencentcloud`       | `Tencent_SecretId`, `Tencent_SecretKey`                                                                   | Cloud           |
| DNSPod         | `dnspod` / `dp`                  | `DP_Id`, `DP_Key`                                                                                         | Cloud           |
| Huawei Cloud   | `huaweicloud` / `huawei`         | `HUAWEICLOUD_Username`, `HUAWEICLOUD_Password`, `HUAWEICLOUD_DomainName`                                  | Cloud           |
| JD Cloud       | `jdcloud` / `jd`                 | `JD_ACCESS_KEY_ID`, `JD_ACCESS_KEY_SECRET`, `JD_REGION` (optional)                                        | Cloud           |
| AWS Route53    | `aws` / `route53`                | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`                                                              | Cloud           |
| Azure          | `azure`                          | `AZUREDNS_SUBSCRIPTIONID`, `AZUREDNS_TENANTID`, `AZUREDNS_APPID`, `AZUREDNS_CLIENTSECRET`                 | Cloud           |
| Google Cloud   | `gcloud` / `google`              | `GCE_PROJECT` (requires `gcloud` CLI installed and authenticated)                                       | Cloud           |
| DigitalOcean   | `digitalocean` / `do` / `dgon`   | `DO_API_KEY`                                                                                            | Cloud           |
| OVH            | `ovh`                            | `OVH_ENDPOINT` (optional), `OVH_APPLICATION_KEY` / `OVH_AK`, `OVH_APPLICATION_SECRET` / `OVH_AS`, `OVH_CONSUMER_KEY` / `OVH_CK` | Cloud           |
| Linode v4      | `linode` / `linode_v4`           | `LINODE_V4_API_KEY`                                                                                       | VPS / Hosting   |
| Linode v3      | `linode_v3`                      | `LINODE_API_KEY` (deprecated)                                                                             | VPS / Hosting   |
| Vultr          | `vultr`                          | `VULTR_API_KEY`                                                                                           | VPS / Hosting   |
| IONOS          | `ionos`                          | `IONOS_PREFIX`, `IONOS_SECRET`                                                                            | VPS / Hosting   |
| Netlify        | `netlify`                        | `NETLIFY_ACCESS_TOKEN`                                                                                    | VPS / Hosting   |
| DuckDNS        | `duckdns`                        | `DuckDNS_Token`                                                                                           | Free / Community|
| deSEC          | `desec`                          | `DESEC_TOKEN`                                                                                             | Free / Community|
| BunnyCDN       | `bunny` / `bunnycdn`             | `BUNNY_API_KEY`                                                                                           | Free / Community|
| Manual         | `manual` (default)               | None — prints instructions, waits for Enter                                                               | Special         |
| acme-dns       | `acmedns`                        | `ACMEDNS_BASE_URL` (auto-registers if no credentials)                                                     | Special         |
| AcmeProxy      | `acmeproxy`                      | `ACMEPROXY_ENDPOINT`, `ACMEPROXY_USERNAME`, `ACMEPROXY_PASSWORD`                                          | Special         |
| DNSimple       | `dnsimple`                       | `DNSIMPLE_OAUTH_TOKEN` (account ID auto-discovered)                                                         | Domain Registrar|

## Manual Mode

When `--dns-provider` is not specified (defaults to `manual`), the tool prints:

```
=== DNS-01 Challenge ===
Set the following TXT record:

_acme-challenge.example.com  IN  TXT  x7q3...

Press Enter after setting the DNS record...
```

After pressing Enter, the tool proceeds with validation.

## Adding a New Provider

1. Create `src/dns/{provider}.rs`
2. Implement the `DnsProvider` trait:

```rust
use anyhow::Result;
use crate::dns::DnsProvider;

pub struct MyDns { /* fields */ }

impl DnsProvider for MyDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        // Set _acme-challenge.{domain} TXT = {value}
    }
    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        // Remove _acme-challenge.{domain} TXT record
    }
}
```

3. Register in `src/dns/mod.rs`:
   - Add `pub mod mydns;`
   - Add entry in `create_provider()`: `"myprovider" => Ok(Box::new(mydns::MyDns::new()?)),`

## Reference

All providers are ported from [acmesh-official/acme.sh/dnsapi](https://github.com/acmesh-official/acme.sh/tree/master/dnsapi).

## Experimental DNS challenge types

### dns-persist-01 (draft-ietf-acme-dns-persist-00)

Persistent DNS challenge. TXT record is set once and **never cleaned up**, surviving
across renewals. Same DNS provider as `dns-01`.

```sh
acme-tiny-rs ... \
    --challenge-type dns-persist-01 \
    --dns-provider cloudflare
```

### dns-account-01 (draft-ietf-acme-dns-account-01)

Account-scoped DNS challenge. DNS record is set once per account key and reused
for all domains under that account — zero DNS API calls after initial setup.
TXT value = `SHA256(account key JWK thumbprint)`.

```sh
acme-tiny-rs ... \
    --challenge-type dns-account-01 \
    --dns-provider cloudflare
```

## Exec DNS provider

Generic provider that calls external scripts. Configured via environment variables:

| Variable | Purpose |
|----------|---------|
| `ACME_DNS_EXEC_PRESENT` | Path to script: `present.sh <domain> <txt_value>` |
| `ACME_DNS_EXEC_CLEAN`   | Path to script: `clean.sh <domain> <txt_value>` |

```sh
acme-tiny-rs ... \
    --challenge-type dns-01 \
    --dns-provider exec
```

## Integration testing with pebble-challtestsrv

DNS challenge tests use pebble-challtestsrv for real TXT record validation:

1. **pebble-challtestsrv** binds DNS on `:8053` and management API on `:8055`
2. **Pebble** starts with `-dnsserver :8053` to query mock DNS
3. **Exec provider** scripts set TXT records via `curl localhost:8055/set-txt`
4. **Pebble VA** validates `_acme-challenge.<domain>` TXT against mock DNS

Tests cover: `dns-01`, `dns-persist-01`, `dns-account-01` (74 tests total).
