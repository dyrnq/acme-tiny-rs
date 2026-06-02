//! `revoke` subcommand — ACME certificate revocation (RFC 8555 §7.6).

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;

use crate::{parse_account_key, send_signed_request, Directory, USER_AGENT};

/// Build HTTP client for revoke with optional custom CA bundle / insecure mode.
fn build_http_client(ca_bundle: Option<&str>, insecure: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();

    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Some(ref path) = ca_bundle {
        let cert_pem =
            std::fs::read(path).with_context(|| format!("Error reading CA bundle: {path}"))?;
        let cert = reqwest::tls::Certificate::from_pem(&cert_pem)
            .context("Failed to parse CA certificate")?;
        builder = builder.add_root_certificate(cert);
    }

    builder.build().context("Failed to create HTTP client")
}

/// Revoke a certificate signed by the ACME account key.
pub async fn run(
    cert_path: &str,
    account_key_path: &str,
    directory_url: &str,
    reason: Option<u32>,
    ca_bundle: Option<&str>,
    insecure: bool,
) -> Result<()> {
    // 1. Read and parse the certificate → DER, then base64url-encode
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate: {cert_path}"))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_pem)
        .map_err(|e| anyhow!("Invalid certificate PEM: {e}"))?;
    let cert_b64 = URL_SAFE_NO_PAD.encode(&pem.contents);

    // 2. Parse account key for JWS signing
    let signing_key = parse_account_key(account_key_path)?;

    // 3. Build HTTP client with TLS settings
    let client = build_http_client(ca_bundle, insecure)?;

    // 4. Fetch ACME directory
    let directory: serde_json::Value = client
        .get(directory_url)
        .header("User-Agent", USER_AGENT)
        .send()
        .await
        .context("Failed to fetch ACME directory")?
        .json()
        .await
        .context("Invalid directory response")?;

    let revoke_url = directory["revokeCert"].as_str().ok_or_else(|| {
        anyhow!(
            "Server does not support certificate revocation (no revokeCert endpoint in directory)"
        )
    })?;

    // Build Directory struct for nonce fetching
    let dir = Directory {
        new_nonce: directory["newNonce"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing newNonce in directory"))?
            .to_string(),
        new_account: directory["newAccount"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing newAccount in directory"))?
            .to_string(),
        new_order: directory["newOrder"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing newOrder in directory"))?
            .to_string(),
        renewal_info: directory["renewalInfo"].as_str().map(|s| s.to_string()),
        key_change: directory["keyChange"].as_str().map(|s| s.to_string()),
    };

    // 5. Resolve account location (KID) by re-registering —
    //    RFC 8555 §7.3.1: same key → 200 with existing Location
    let acct_payload = json!({"termsOfServiceAgreed": true});
    let (_acct, _, headers) = send_signed_request(
        &client,
        &dir.new_account,
        Some(&acct_payload),
        "Error looking up account",
        &signing_key,
        &None,
        &dir,
    )
    .await?;

    let acct_location = headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 6. Build revocation payload
    let mut payload = json!({ "certificate": cert_b64 });
    if let Some(r) = reason {
        if r > 10 {
            bail!("Invalid revocation reason: {r} (must be 0-10 per RFC 5280)");
        }
        payload["reason"] = json!(r);
    }

    // 7. Send signed revocation request with account KID
    let (resp, status, _headers) = send_signed_request(
        &client,
        revoke_url,
        Some(&payload),
        "Error revoking certificate",
        &signing_key,
        &acct_location,
        &dir,
    )
    .await?;

    if status.is_success() {
        println!("Certificate revoked successfully.");
        Ok(())
    } else {
        bail!("Revocation failed with HTTP status: {status} — {resp}");
    }
}
