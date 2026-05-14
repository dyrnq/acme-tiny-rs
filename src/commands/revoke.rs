//! `revoke` subcommand — ACME certificate revocation (RFC 8555 §7.6).

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;

use crate::{send_signed_request, Directory, parse_account_key};

/// Revoke a certificate signed by the ACME account key.
pub async fn run(
    cert_path: &str,
    account_key_path: &str,
    directory_url: &str,
    reason: Option<u32>,
) -> Result<()> {
    // 1. Read and parse the certificate → DER, then base64url-encode
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate: {cert_path}"))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_pem)
        .map_err(|e| anyhow!("Invalid certificate PEM: {e}"))?;
    let cert_b64 = URL_SAFE_NO_PAD.encode(&pem.contents);

    // 2. Parse account key for JWS signing
    let signing_key = parse_account_key(account_key_path)?;

    // 3. Fetch ACME directory
    let client = reqwest::Client::new();
    let directory: serde_json::Value = client
        .get(directory_url)
        .header("User-Agent", concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION")))
        .send().await.context("Failed to fetch ACME directory")?
        .json().await.context("Invalid directory response")?;

    let revoke_url = directory["revokeCert"].as_str()
        .ok_or_else(|| anyhow!("Server does not support certificate revocation (no revokeCert endpoint in directory)"))?;

    // Build Directory struct for nonce fetching
    let dir = Directory {
        new_nonce: directory["newNonce"].as_str()
            .ok_or_else(|| anyhow!("Missing newNonce in directory"))?.to_string(),
        new_account: directory["newAccount"].as_str()
            .ok_or_else(|| anyhow!("Missing newAccount in directory"))?.to_string(),
        new_order: directory["newOrder"].as_str()
            .ok_or_else(|| anyhow!("Missing newOrder in directory"))?.to_string(),
    };

    // 4. Build revocation payload
    let mut payload = json!({ "certificate": cert_b64 });
    if let Some(r) = reason {
        if r > 10 {
            bail!("Invalid revocation reason: {r} (must be 0-10 per RFC 5280)");
        }
        payload["reason"] = json!(r);
    }

    // 5. Send signed revocation request (JWK-based signing, no account URL)
    let (_resp, status, _headers) = send_signed_request(
        &client,
        revoke_url,
        Some(&payload),
        "Error revoking certificate",
        &signing_key,
        &None,
        &dir,
    ).await?;

    if status == 200 {
        println!("Certificate revoked successfully.");
        Ok(())
    } else {
        bail!("Revocation failed with unexpected HTTP status: {status}");
    }
}
