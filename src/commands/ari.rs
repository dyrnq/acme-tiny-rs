//! `ari` subcommand — ACME Renewal Information (RFC 9773) check.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::io::Read;
use x509_parser::prelude::*;

/// Authority Key Identifier OID (RFC 5280 §4.2.1.1)
const OID_AKI: &str = "2.5.29.35";

/// Strip DER wrappers from AKI extension value to get raw key hash.
fn extract_aki_key_hash(value: &[u8]) -> Option<&[u8]> {
    // ext.value = SEQUENCE([0] IMPLICIT OCTET STRING{key_hash})
    let off = if value.first() == Some(&0x30) { 2 } else { return None; }; // SEQUENCE
    if off >= value.len() { return None; }
    if value.get(off) != Some(&0x80) { return None; } // [0] IMPLICIT
    let len = *value.get(off + 1)? as usize;
    value.get(off + 2 .. off + 2 + len)
}

/// Query the ACME renewalInfo endpoint and output JSON to stdout.
pub async fn run(cert_path: &str, directory_url: &str, insecure: bool, verbose: u8) -> Result<()> {
    if verbose >= 1 {
        eprintln!("[ari] Reading certificate from {cert_path}");
    }
    let cert_pem = if cert_path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)
            .with_context(|| "Failed to read certificate from stdin")?;
        buf
    } else {
        std::fs::read(cert_path)
            .with_context(|| format!("Failed to read {cert_path}"))?
    };
    let (_, pem) = x509_parser::pem::pem_to_der(&cert_pem)
        .map_err(|e| anyhow!("Invalid PEM: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .context("Failed to parse certificate")?;

    // Extract AKI key hash from extension value.
    let aki = cert.extensions()
        .iter()
        .find(|ext| ext.oid.to_string() == OID_AKI)
        .and_then(|ext| extract_aki_key_hash(ext.value.as_ref()).map(|s| s.to_vec()))
        .ok_or_else(|| anyhow!(r#"{{"renew":false,"reason":"no aki"}}"#))?;

    let serial = cert.raw_serial().to_vec();

    if verbose >= 2 {
        eprintln!("[ari] AKI: {} bytes", aki.len());
        eprintln!("[ari] Serial: {} bytes", serial.len());
    }

    let b64 = |d: &[u8]| URL_SAFE_NO_PAD.encode(d);
    let cert_id = format!("{}.{}", b64(&aki), b64(&serial));

    if verbose >= 1 {
        eprintln!("[ari] certID = {cert_id}");
    }

    let client = if insecure {
        reqwest::Client::builder().danger_accept_invalid_certs(true).build().context("Failed to create HTTP client")?
    } else {
        reqwest::Client::new()
    };

    if verbose >= 1 {
        eprintln!("[ari] GET {directory_url}");
    }

    let directory: serde_json::Value = client
        .get(directory_url)
        .header("User-Agent", concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION")))
        .send().await.context("Failed to fetch ACME directory")?
        .json().await.context("Invalid directory response")?;

    let renewal_url = directory["renewalInfo"].as_str()
        .ok_or_else(|| anyhow!(r#"{{"renew":false,"reason":"no ari endpoint"}}"#))?;

    if verbose >= 1 {
        eprintln!("[ari] renewalInfo endpoint: {renewal_url}");
    }

    let url = if renewal_url.starts_with("http") {
        format!("{renewal_url}/{cert_id}")
    } else {
        let dir_url = reqwest::Url::parse(directory_url)
            .context("Invalid directory URL")?;
        format!("{}://{}{}/{}/{}",
            dir_url.scheme(),
            dir_url.host_str().unwrap_or(""),
            if let Some(port) = dir_url.port() { format!(":{port}") } else { String::new() },
            renewal_url.trim_matches('/'),
            cert_id)
    };

    if verbose >= 2 {
        eprintln!("[ari] GET {url}");
    }

    let resp = client
        .get(&url)
        .header("User-Agent", concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION")))
        .send().await.context("Failed to query ARI endpoint")?;

    if verbose >= 1 {
        eprintln!("[ari] Response: HTTP {}", resp.status());
    }

    if resp.status() == 404 {
        println!(r#"{{"renew":false,"reason":"no suggestion"}}"#);
        return Ok(());
    }

    if !resp.status().is_success() {
        bail!("ARI query failed: HTTP {}", resp.status());
    }

    let info: serde_json::Value = resp.json().await.context("Invalid ARI response")?;
    if verbose >= 3 {
        eprintln!("[ari] Response body: {}", serde_json::to_string_pretty(&info)?);
    }
    println!("{info}");
    Ok(())
}
