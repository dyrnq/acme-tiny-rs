//! `ari` subcommand — ACME Renewal Information (RFC 9773) check.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use x509_parser::prelude::*;

/// Query the ACME renewalInfo endpoint and output JSON to stdout.
pub async fn run(cert_path: &str, directory_url: &str) -> Result<()> {
    // Read and parse the certificate
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read {cert_path}"))?;
    let (_, pem) = x509_parser::pem::pem_to_der(&cert_pem)
        .map_err(|e| anyhow!("Invalid PEM: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .context("Failed to parse certificate")?;

    // Extract AKI extension (OID 2.5.29.35)
    let aki = cert.extensions()
        .iter()
        .find(|ext| ext.oid.to_string() == "2.5.29.35")
        .map(|ext| ext.value.to_vec())
        .ok_or_else(|| anyhow!("No Authority Key Identifier in certificate"))?;

    // Serial number
    let serial = cert.raw_serial().to_vec();

    // certID = base64url(AKI) + "." + base64url(serial)
    let b64 = |d: &[u8]| URL_SAFE_NO_PAD.encode(d);
    let cert_id = format!("{}.{}", b64(&aki), b64(&serial));

    // Fetch directory to find renewalInfo endpoint
    let client = reqwest::Client::new();
    let directory: serde_json::Value = client
        .get(directory_url)
        .header("User-Agent", concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION")))
        .send().await.context("Failed to fetch ACME directory")?
        .json().await.context("Invalid directory response")?;

    let renewal_url = directory["renewalInfo"].as_str()
        .ok_or_else(|| anyhow!(r#"{{"renew":false,"reason":"no ari endpoint"}}"#))?;

    // Query renewalInfo for this certificate
    let url = format!("{renewal_url}/{cert_id}");
    let resp = client
        .get(&url)
        .header("User-Agent", concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION")))
        .send().await.context("Failed to query ARI endpoint")?;

    if resp.status() == 404 {
        println!(r#"{{"renew":false,"reason":"no suggestion"}}"#);
        return Ok(());
    }

    if !resp.status().is_success() {
        bail!("ARI query failed: HTTP {}", resp.status());
    }

    let info: serde_json::Value = resp.json().await.context("Invalid ARI response")?;
    println!("{info}");
    Ok(())
}
