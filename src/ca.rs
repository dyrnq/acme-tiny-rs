//! ACME Certificate Authority preset registry.
//!
//! This module provides a curated list of known ACME CAs with their directory URLs
//! and metadata, allowing users to switch between CAs using short names.
//!
//! # Example
//!
//! ```bash
//! # Use Let's Encrypt (default)
//! acme-tiny-rs --server letsencrypt --account-key ...
//!
//! # Use ZeroSSL
//! acme-tiny-rs --server zerossl --account-key ...
//!
//! # Use custom CA
//! acme-tiny-rs --server "https://my-ca.example.com/directory" --account-key ...
//! ```

/// Represents a known ACME Certificate Authority.
#[derive(Debug, Clone)]
pub struct KnownCA {
    /// Short identifier (e.g. "letsencrypt", "zerossl")
    pub id: &'static str,
    /// Human-readable name
    pub name: &'static str,
    /// Production directory URL
    pub directory_url: &'static str,
    /// Website URL
    pub website: &'static str,
    /// Whether EAB (External Account Binding) is required
    pub eab_required: bool,
    /// Whether wildcard certificates are supported
    pub wildcard_supported: bool,
    /// Notes about this CA
    pub notes: &'static str,
}

/// Registry of known ACME CAs, ordered by recommendation priority.
pub const KNOWN_CAS: &[KnownCA] = &[
    KnownCA {
        id: "letsencrypt",
        name: "Let's Encrypt",
        directory_url: "https://acme-v02.api.letsencrypt.org/directory",
        website: "https://letsencrypt.org",
        eab_required: false,
        wildcard_supported: true,
        notes: "Default CA, widely supported, free certificates",
    },
    KnownCA {
        id: "letsencrypt-staging",
        name: "Let's Encrypt (Staging)",
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
        website: "https://letsencrypt.org/docs/staging-environment/",
        eab_required: false,
        wildcard_supported: true,
        notes: "Testing environment, rate limits are much higher, untrusted certs",
    },
    KnownCA {
        id: "zerossl",
        name: "ZeroSSL",
        directory_url: "https://acme.zerossl.com/v2/DV90",
        website: "https://zerossl.com",
        eab_required: true,
        wildcard_supported: true,
        notes: "Free tier available (3 certs/90 days), requires EAB registration",
    },
    KnownCA {
        id: "buypass",
        name: "Buypass Go SSL",
        directory_url: "https://api.buypass.com/acme/directory",
        website: "https://www.buypass.com/ssl/products/go-ssl",
        eab_required: true,
        wildcard_supported: true,
        notes: "Free certificates, requires EAB, based in Norway",
    },
    KnownCA {
        id: "buypass-staging",
        name: "Buypass Go SSL (Staging)",
        directory_url: "https://api.test4.buypass.no/acme/directory",
        website: "https://www.buypass.com/ssl/products/go-ssl",
        eab_required: true,
        wildcard_supported: true,
        notes: "Buypass testing environment, untrusted certs",
    },
    KnownCA {
        id: "sslcom",
        name: "SSL.com",
        directory_url: "https://acme.ssl.com/sslcom-dv-rsa",
        website: "https://www.ssl.com",
        eab_required: true,
        wildcard_supported: true,
        notes: "Free 90-day certs, requires EAB, ECDSA available",
    },
    KnownCA {
        id: "google",
        name: "Google Trust Services",
        directory_url: "https://dv.acme-v02.api.pki.goog/directory",
        website: "https://pki.goog",
        eab_required: true,
        wildcard_supported: false,
        notes: "Google's public ACME CA, requires EAB",
    },
    KnownCA {
        id: "step",
        name: "Smallstep CA (local)",
        directory_url: "https://localhost:9000/acme/acme/directory",
        website: "https://smallstep.com",
        eab_required: false,
        wildcard_supported: true,
        notes: "Self-hosted ACME server for internal PKI",
    },
    KnownCA {
        id: "pebble",
        name: "Pebble (local test)",
        directory_url: "https://localhost:14000/dir",
        website: "https://github.com/letsencrypt/pebble",
        eab_required: false,
        wildcard_supported: true,
        notes: "Local ACME test server, not for production",
    },
    KnownCA {
        id: "pebble-eab",
        name: "Pebble with EAB (local test)",
        directory_url: "https://localhost:14001/dir",
        website: "https://github.com/letsencrypt/pebble",
        eab_required: true,
        wildcard_supported: true,
        notes: "Pebble test server with EAB enabled",
    },
];

/// Result of resolving a server identifier.
#[derive(Debug, Clone)]
pub enum ResolvedCA {
    /// Matched a known CA preset
    Known(KnownCA),
    /// Custom URL provided
    Custom(String),
}

impl ResolvedCA {
    /// Get the directory URL for this CA.
    pub fn directory_url(&self) -> String {
        match self {
            ResolvedCA::Known(ca) => ca.directory_url.to_string(),
            ResolvedCA::Custom(url) => url.clone(),
        }
    }

    /// Get the human-readable name.
    pub fn name(&self) -> String {
        match self {
            ResolvedCA::Known(ca) => ca.name.to_string(),
            ResolvedCA::Custom(url) => url.clone(),
        }
    }
}

/// Resolve a server identifier to a CA.
///
/// Accepts:
/// - A known CA preset ID (case-insensitive): "letsencrypt", "zerossl", etc.
/// - A full URL starting with "http://" or "https://"
///
/// Returns an error if the preset ID is not found.
pub fn resolve(server: &str) -> anyhow::Result<ResolvedCA> {
    // Check if it's a URL
    if server.starts_with("http://") || server.starts_with("https://") {
        return Ok(ResolvedCA::Custom(server.to_string()));
    }

    // Try to match known CA (case-insensitive)
    let server_lower = server.to_lowercase();
    for ca in KNOWN_CAS {
        if ca.id.to_lowercase() == server_lower {
            return Ok(ResolvedCA::Known(ca.clone()));
        }
    }

    anyhow::bail!(
        "Unknown CA server: '{}'\n\nAvailable presets:\n{}",
        server,
        list_presets()
    );
}

/// Generate a formatted list of all known CA presets.
pub fn list_presets() -> String {
    let mut lines = Vec::new();
    for ca in KNOWN_CAS {
        let eab = if ca.eab_required { " [EAB required]" } else { "" };
        lines.push(format!("  {:<25} {}{}", ca.id, ca.name, eab));
    }
    lines.join("\n")
}

/// Print a detailed table of all known CAs.
pub fn print_ca_table() {
    println!();
    println!("{:<25} {:<30} {:<8} {:<8} {}", "ID", "Name", "EAB", "Wildcard", "Notes");
    println!("{}", "-".repeat(120));
    for ca in KNOWN_CAS {
        let eab = if ca.eab_required { "Yes" } else { "No" };
        let wildcard = if ca.wildcard_supported { "Yes" } else { "No" };
        println!("{:<25} {:<30} {:<8} {:<8} {}", ca.id, ca.name, eab, wildcard, ca.notes);
    }
    println!();
    println!("Use --server <id> to select a CA, or provide a full URL.");
    println!("Example: --server zerossl");
    println!("Example: --server https://my-ca.example.com/directory");
}

/// Fetch ACME directory and print raw JSON.
pub async fn inspect_ca(server: &str, verbose: u8) -> anyhow::Result<()> {
    let url = match resolve(server)? {
        ResolvedCA::Known(ca) => ca.directory_url.to_string(),
        ResolvedCA::Custom(u) => u,
    };
    if verbose >= 1 {
        eprintln!("[inspect-ca] GET {url}");
    }
    let client = reqwest::Client::new();
    let resp = client.get(&url)
        .header("User-Agent", concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION")))
        .send().await?;
    if verbose >= 1 {
        eprintln!("[inspect-ca] Response: HTTP {}", resp.status());
    }
    let dir: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&dir)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_url() {
        let result = resolve("https://example.com/directory").unwrap();
        match result {
            ResolvedCA::Custom(url) => assert_eq!(url, "https://example.com/directory"),
            _ => panic!("Expected Custom variant"),
        }
    }

    #[test]
    fn test_resolve_known_ca() {
        let result = resolve("letsencrypt").unwrap();
        match result {
            ResolvedCA::Known(ca) => assert_eq!(ca.name, "Let's Encrypt"),
            _ => panic!("Expected Known variant"),
        }
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let result = resolve("ZeroSSL").unwrap();
        match result {
            ResolvedCA::Known(ca) => assert_eq!(ca.id, "zerossl"),
            _ => panic!("Expected Known variant"),
        }
    }

    #[test]
    fn test_resolve_unknown() {
        let result = resolve("unknown-ca");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown CA server"));
        assert!(err.contains("Available presets"));
    }

    #[test]
    fn test_resolve_http_url() {
        let result = resolve("http://localhost:14000/dir").unwrap();
        match result {
            ResolvedCA::Custom(url) => assert_eq!(url, "http://localhost:14000/dir"),
            _ => panic!("Expected Custom variant"),
        }
    }

    #[test]
    fn test_list_presets_contains() {
        let list = list_presets();
        assert!(list.contains("letsencrypt"));
        assert!(list.contains("zerossl"));
        assert!(list.contains("buypass"));
        assert!(list.contains("[EAB required]"));
    }

    #[test]
    fn test_known_cas_have_unique_ids() {
        let ids: Vec<&str> = KNOWN_CAS.iter().map(|c| c.id).collect();
        let unique_ids: std::collections::HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique_ids.len(), "Duplicate CA IDs found");
    }
}
