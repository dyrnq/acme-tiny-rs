/// CNAME auto-follow for DNS-01 / DNS-persist-01 challenge delegation.
///
/// When a user creates a CNAME record like:
///   `_acme-challenge.example.com CNAME _acme-challenge.delegated.net.`
/// the DNS challenge FQDN should resolve through the CNAME chain to find the
/// actual target where the TXT record will be written.
///
/// This is modeled after lego's `lookupCNAME` — zero configuration, automatic
/// discovery, default-on, and harmless when no CNAME exists.

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use std::str::FromStr;

/// Maximum CNAME chain length (matches lego's limit).
const MAX_CNAME_HOPS: usize = 50;

/// Resolve the base domain that the ACME DNS challenge should use.
///
/// This constructs the full `_acme-challenge.{domain}` FQDN, looks up any
/// CNAME chain, and extracts the base domain from the final target.
///
/// If `_acme-challenge.example.com` has a CNAME to `_acme-challenge.other.com`,
/// this returns `"other.com"`. If no CNAME exists, returns `domain` unchanged.
///
/// This is the primary entry point used before calling `provider.present()`.
pub async fn resolve_challenge_domain(domain: &str) -> String {
    let challenge_fqdn = format!("_acme-challenge.{}", domain);

    // Build resolver using hickory-resolver 0.25 builder API
    let resolver = match TokioResolver::builder_tokio() {
        Ok(builder) => builder.build(),
        Err(e) => {
            log::debug!("Failed to build DNS resolver: {} (using domain as-is)", e);
            return domain.to_string();
        }
    };

    let target = follow_cname(&resolver, &challenge_fqdn).await;

    // Extract base domain from the challenge FQDN.
    // The CNAME target will be something like `_acme-challenge.delegated.net.`
    // We need to strip the `_acme-challenge.` prefix to get the base domain
    // that the DNS provider API expects.
    if target != challenge_fqdn {
        // The target is a CNAME; extract the base domain.
        // The CNAME target for DNS-01 always starts with `_acme-challenge.`
        let prefix = "_acme-challenge.";
        target
            .strip_prefix(prefix)
            .and_then(|s| s.strip_suffix('.').or(Some(s)))
            .unwrap_or(&target)
            .to_string()
    } else {
        // No CNAME found, use the original domain
        domain.to_string()
    }
}

/// Follow CNAME records starting from `fqdn` and return the final target.
///
/// Returns the original `fqdn` if no CNAME is found or any error occurs.
async fn follow_cname(resolver: &TokioResolver, fqdn: &str) -> String {
    let mut current = fqdn.to_string();

    for _ in 0..MAX_CNAME_HOPS {
        let name = match hickory_resolver::Name::from_str(&current) {
            Ok(n) => n,
            Err(_) => {
                log::debug!("Invalid domain name for CNAME lookup: {}", current);
                break;
            }
        };

        match resolver.lookup(name.clone(), RecordType::CNAME).await {
            Ok(lookup) => {
                // In hickory-resolver 0.25, lookup iterates over &RData directly.
                let mut found_cname = false;
                for rdata in lookup.iter() {
                    if let RData::CNAME(cname_data) = rdata {
                        let target = cname_data.0.to_string();
                        // DNS names have a trailing dot; strip it
                        let target = target.strip_suffix('.').unwrap_or(&target);
                        if target != current {
                            log::info!("CNAME delegation: {} -> {}", current, target);
                            current = target.to_string();
                            found_cname = true;
                        }
                    }
                }
                // If no CNAME record was found in this lookup, we're done
                if !found_cname {
                    break;
                }
            }
            Err(e) => {
                // No CNAME record or DNS error — that's OK, continue with current
                log::debug!("CNAME lookup for {}: {} (using as-is)", current, e);
                break;
            }
        }
    }

    current
}
