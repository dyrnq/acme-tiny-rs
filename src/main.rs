use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::Parser;
use log::{info, LevelFilter};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey};
use rsa::pkcs1v15;
use signature::{Signer, SignatureEncoding};
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p256::SecretKey as P256SecretKey;
use p384::SecretKey as P384SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::FromDer;
use x509_parser::extensions::{ParsedExtension, GeneralName};

const DEFAULT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const USER_AGENT: &str = concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION"));

mod dns;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "acme-tiny-rs",
    about = concat!("A tiny ACME client to issue and renew TLS certs from Let's Encrypt — v", env!("CARGO_PKG_VERSION")),
    after_help = "Example:\n  acme-tiny-rs --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/challenges/ > signed_chain.crt"
)]
struct Cli {
    /// Path to your Let's Encrypt account private key
    #[arg(long = "account-key")]
    account_key: String,

    /// Path to your certificate signing request (CSR)
    #[arg(long = "csr")]
    csr: String,

    /// Path to the .well-known/acme-challenge/ directory
    #[arg(long = "acme-dir")]
    acme_dir: String,

    /// Suppress output except for errors
    #[arg(long = "quiet")]
    quiet: bool,

    /// Disable checking if the challenge file is hosted correctly
    #[arg(long = "disable-check")]
    disable_check: bool,

    /// Certificate authority directory URL (default: Let's Encrypt)
    #[arg(long = "directory-url", default_value = DEFAULT_DIRECTORY_URL)]
    directory_url: String,

    /// DEPRECATED! Use --directory-url instead
    #[arg(long = "ca")]
    ca: Option<String>,

    /// Contact details (e.g. mailto:aaa@bbb.com) for your account-key
    #[arg(long = "contact", num_args = 0..)]
    contact: Option<Vec<String>>,

    /// What port to use when self-checking the challenge file
    #[arg(long = "check-port")]
    check_port: Option<u16>,

    /// Challenge type: http-01 (default) or dns-01
    #[arg(long = "challenge-type", default_value = "http-01")]
    challenge_type: String,

    /// DNS provider for dns-01 challenge: manual, cloudflare (cf)
    #[arg(long = "dns-provider", default_value = "manual")]
    dns_provider: String,

    /// EAB Key Identifier (for External Account Binding)
    #[arg(long = "eab-kid")]
    eab_kid: Option<String>,

    /// EAB HMAC Key (base64url-encoded, for External Account Binding)
    #[arg(long = "eab-hmac-key")]
    eab_hmac_key: Option<String>,

    /// Path to additional CA certificate bundle for TLS verification
    #[arg(long = "ca-bundle")]
    ca_bundle: Option<String>,

    /// Disable TLS certificate verification (testing only)
    #[arg(long = "insecure", hide = true)]
    insecure: bool,
}

// ---------------------------------------------------------------------------
// JSON types for ACME protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Serialize)]
struct JwsBody {
    protected: String,
    payload: String,
    signature: String,
}

// ---------------------------------------------------------------------------
// Unified signing key (RSA or ECDSA)
// ---------------------------------------------------------------------------

enum SigningKey {
    Rsa {
        key: RsaPrivateKey,
        jwk: serde_json::Value,
    },
    EcdsaP256 {
        key: P256SigningKey,
        jwk: serde_json::Value,
    },
    EcdsaP384 {
        key: P384SigningKey,
        jwk: serde_json::Value,
    },
}

impl SigningKey {
    fn jwk(&self) -> &serde_json::Value {
        match self {
            SigningKey::Rsa { jwk, .. }
            | SigningKey::EcdsaP256 { jwk, .. }
            | SigningKey::EcdsaP384 { jwk, .. } => jwk,
        }
    }

    fn alg(&self) -> &'static str {
        match self {
            SigningKey::Rsa { .. } => "RS256",
            SigningKey::EcdsaP256 { .. } => "ES256",
            SigningKey::EcdsaP384 { .. } => "ES384",
        }
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SigningKey::Rsa { key, .. } => {
                let signing_key = pkcs1v15::SigningKey::<Sha256>::new(key.clone());
                Ok(signing_key.sign(data).to_vec())
            }
            SigningKey::EcdsaP256 { key, .. } => {
                let sig: p256::ecdsa::Signature = key.sign(data);
                Ok(sig.to_vec())
            }
            SigningKey::EcdsaP384 { key, .. } => {
                let sig: p384::ecdsa::Signature = key.sign(data);
                Ok(sig.to_vec())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: base64url encode without padding
// ---------------------------------------------------------------------------

pub(crate) fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async fn do_request(
    client: &reqwest::Client,
    url: &str,
    data: Option<Vec<u8>>,
    err_msg: &str,
) -> Result<(serde_json::Value, reqwest::StatusCode, reqwest::header::HeaderMap)> {
    let data_str = data
        .as_ref()
        .map(|d| String::from_utf8_lossy(d).to_string());
    let resp = if let Some(body) = data {
        client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .header("User-Agent", USER_AGENT)
            .body(body)
            .send()
            .await
    } else {
        client
            .get(url)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
    }
    .context(format!("{err_msg}: failed to send request to {url}"))?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let body_text = resp.text().await.unwrap_or_default();
    let json: serde_json::Value =
        serde_json::from_str(&body_text).unwrap_or(serde_json::Value::Null);

    // Validate HTTP status (ACME success codes: 200, 201, 204)
    if status != reqwest::StatusCode::OK
        && status != reqwest::StatusCode::CREATED
        && status != reqwest::StatusCode::NO_CONTENT
        && !(status == reqwest::StatusCode::BAD_REQUEST
            && json.get("type").and_then(|t| t.as_str())
                .map_or(false, |t| t == "urn:ietf:params:acme:error:badNonce"))
    {
        bail!(
            "{err_msg}:\nUrl: {url}\nData: {}\nResponse Code: {status}\nResponse: {json}",
            data_str.as_deref().unwrap_or("None")
        );
    }

    Ok((json, status, headers))
}

// ---------------------------------------------------------------------------
// Signed request helper (JWS with RS256)
// ---------------------------------------------------------------------------

async fn send_signed_request(
    client: &reqwest::Client,
    url: &str,
    payload: Option<&serde_json::Value>,
    err_msg: &str,
    signing_key: &SigningKey,
    acct_location: &Option<String>,
    directory: &Directory,
) -> Result<(serde_json::Value, reqwest::StatusCode, reqwest::header::HeaderMap)> {
    send_signed_request_inner(client, url, payload, err_msg, signing_key, acct_location, directory, 0).await
}

async fn send_signed_request_inner(
    client: &reqwest::Client,
    url: &str,
    payload: Option<&serde_json::Value>,
    err_msg: &str,
    signing_key: &SigningKey,
    acct_location: &Option<String>,
    directory: &Directory,
    depth: u32,
) -> Result<(serde_json::Value, reqwest::StatusCode, reqwest::header::HeaderMap)> {
    let payload64 = match payload {
        None => String::new(),
        Some(p) => b64(serde_json::to_string(p).unwrap().as_bytes()),
    };

    // Get a fresh nonce
    let nonce_resp = do_request(client, &directory.new_nonce, None, "Error getting nonce").await?;
    let nonce = nonce_resp
        .2
        .get("Replay-Nonce")
        .ok_or_else(|| anyhow!("Missing Replay-Nonce header"))?
        .to_str()?
        .to_string();

    let alg = signing_key.alg();
    let jwk = signing_key.jwk();

    let mut protected: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    protected.insert("url".into(), serde_json::Value::String(url.to_string()));
    protected.insert("alg".into(), serde_json::Value::String(alg.to_string()));
    protected.insert("nonce".into(), serde_json::Value::String(nonce));

    if let Some(ref kid) = acct_location {
        protected.insert("kid".into(), serde_json::Value::String(kid.clone()));
    } else {
        protected.insert("jwk".into(), jwk.clone());
    }

    let protected64 = b64(serde_json::to_string(&protected).unwrap().as_bytes());
    let signing_input = format!("{protected64}.{payload64}");

    let signature = signing_key.sign(signing_input.as_bytes())?;

    let jws = JwsBody {
        protected: protected64,
        payload: payload64,
        signature: b64(&signature),
    };

    let data = serde_json::to_vec(&jws)?;
    let result = do_request(client, url, Some(data), err_msg).await?;

    // Handle badNonce retry (up to 100 retries like the python version)
    if result.1 == reqwest::StatusCode::BAD_REQUEST
        && result
            .0
            .get("type")
            .and_then(|t| t.as_str())
            .map_or(false, |t| t == "urn:ietf:params:acme:error:badNonce")
    {
        if depth >= 100 {
            bail!("Too many badNonce retries");
        }
        return Box::pin(send_signed_request_inner(
            client, url, payload, err_msg, signing_key, acct_location, directory, depth + 1,
        ))
        .await;
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Poll until complete
// ---------------------------------------------------------------------------

async fn poll_until_not(
    client: &reqwest::Client,
    url: &str,
    pending_statuses: &[&str],
    err_msg: &str,
    signing_key: &SigningKey,
    acct_location: &Option<String>,
    directory: &Directory,
) -> Result<serde_json::Value> {
    let start = Instant::now();
    let timeout = Duration::from_secs(3600);
    #[allow(unused_assignments)]
    let mut result = serde_json::Value::Null;
    let mut first = true;

    loop {
        if start.elapsed() > timeout {
            bail!("Polling timeout");
        }
        if !first {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        first = false;

        let (res, _, _) = send_signed_request(
            client, url, None, err_msg, signing_key, acct_location, directory,
        )
        .await?;
        result = res;

        let status = result["status"].as_str().unwrap_or("");
        if !pending_statuses.contains(&status) {
            break;
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Parse RSA account key: extract public key modulus and exponent (native Rust)
// Replaces: openssl rsa -in account.key -noout -text
// ---------------------------------------------------------------------------

fn parse_account_key(path: &str) -> Result<SigningKey> {
    info!("Parsing account key...");
    let pem_data = fs::read_to_string(path)
        .with_context(|| format!("Error reading account key file: {path}"))?;

    // Detect key type from PEM header
    if pem_data.contains("RSA PRIVATE KEY") {
        parse_rsa_key(&pem_data)
    } else if pem_data.contains("EC PRIVATE KEY") {
        parse_ec_key(&pem_data)
    } else if pem_data.contains("PRIVATE KEY") {
        // PKCS#8 format — try RSA first, then EC
        parse_rsa_key(&pem_data)
            .or_else(|_| parse_ec_key(&pem_data))
    } else {
        bail!("Unsupported key format in {path}");
    }
}

fn parse_rsa_key(pem_data: &str) -> Result<SigningKey> {
    let private_key = RsaPrivateKey::from_pkcs1_pem(pem_data)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem_data))
        .context("Failed to parse RSA private key (tried PKCS#1 and PKCS#8 PEM formats)")?;

    let public_key = private_key.to_public_key();
    let n = public_key.n();
    let e = public_key.e();

    let n_bytes = n.to_bytes_be();
    let e_bytes = e.to_bytes_be();

    let jwk = serde_json::json!({
        "e": b64(&e_bytes),
        "kty": "RSA",
        "n": b64(&n_bytes),
    });

    Ok(SigningKey::Rsa {
        key: private_key,
        jwk,
    })
}

fn parse_ec_key(pem_data: &str) -> Result<SigningKey> {
    // Handle multi-block PEM (e.g., openssl ecparam -genkey outputs EC PARAMETERS + EC PRIVATE KEY)
    let blocks = extract_pem_blocks(pem_data);
    let last_error = || anyhow!("Failed to parse EC private key (tried P-256 and P-384, SEC1 and PKCS#8)");

    for block in &blocks {
        // Try P-256 first, then P-384 — both SEC1 and PKCS#8
        if let Ok(secret) = P256SecretKey::from_sec1_pem(block) {
            return build_ec_p256_key(secret);
        }
        if let Ok(secret) = P384SecretKey::from_sec1_pem(block) {
            return build_ec_p384_key(secret);
        }
        if let Ok(secret) = P256SecretKey::from_pkcs8_pem(block) {
            return build_ec_p256_key(secret);
        }
        if let Ok(secret) = P384SecretKey::from_pkcs8_pem(block) {
            return build_ec_p384_key(secret);
        }
    }
    Err(last_error())
}

fn build_ec_p256_key(secret: P256SecretKey) -> Result<SigningKey> {
    let signing_key = P256SigningKey::from(secret);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let jwk = serde_json::json!({
        "crv": "P-256",
        "kty": "EC",
        "x": b64(point.x().ok_or_else(|| anyhow!("Missing EC x coordinate"))?),
        "y": b64(point.y().ok_or_else(|| anyhow!("Missing EC y coordinate"))?),
    });
    Ok(SigningKey::EcdsaP256 { key: signing_key, jwk })
}

fn build_ec_p384_key(secret: P384SecretKey) -> Result<SigningKey> {
    let signing_key = P384SigningKey::from(secret);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let jwk = serde_json::json!({
        "crv": "P-384",
        "kty": "EC",
        "x": b64(point.x().ok_or_else(|| anyhow!("Missing EC x coordinate"))?),
        "y": b64(point.y().ok_or_else(|| anyhow!("Missing EC y coordinate"))?),
    });
    Ok(SigningKey::EcdsaP384 { key: signing_key, jwk })
}

/// Extract individual PEM blocks from data that may contain multiple blocks
fn extract_pem_blocks(pem_data: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut in_block = false;

    for line in pem_data.lines() {
        if line.starts_with("-----BEGIN ") {
            if in_block {
                // Start of new block while in one — save previous
                current.push_str("-----END-----\n");
                blocks.push(std::mem::take(&mut current));
            }
            in_block = true;
            current.push_str(line);
            current.push('\n');
        } else if in_block {
            current.push_str(line);
            current.push('\n');
            if line.starts_with("-----END ") {
                blocks.push(std::mem::take(&mut current));
                in_block = false;
            }
        }
    }
    // If the file doesn't have proper PEM markers, just return the whole thing
    if blocks.is_empty() {
        blocks.push(pem_data.to_string());
    }
    blocks
}

/// Build canonical JWK JSON (sorted keys, no whitespace) for thumbprint computation (RFC 7638)
fn canonical_jwk_json(jwk: &serde_json::Value) -> Result<String> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| anyhow!("JWK is not a JSON object"))?;
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    let mut parts = Vec::new();
    for k in &keys {
        let v = &obj[*k];
        let v_str = match v {
            serde_json::Value::String(s) => format!("\"{s}\""),
            _ => serde_json::to_string(v)?,
        };
        parts.push(format!("\"{k}\":{v_str}"));
    }
    Ok(format!("{{{}}}", parts.join(",")))
}

// ---------------------------------------------------------------------------
// Parse CSR: extract domains (CN + SAN) using native Rust parser
// Replaces: openssl req -in csr -noout -text
// ---------------------------------------------------------------------------

fn parse_csr(path: &str) -> Result<Vec<String>> {
    info!("Parsing CSR...");
    let csr_data = fs::read(path)
        .with_context(|| format!("Error loading CSR file: {path}"))?;

    // Try PEM first, then raw DER
    let csr_der = if csr_data.starts_with(b"-----") {
        // PEM format - extract the base64 body
        let pem_str = std::str::from_utf8(&csr_data)
            .context("CSR PEM is not valid UTF-8")?;
        let base64_body: String = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        STANDARD
            .decode(&base64_body.replace(&['\n', '\r'][..], ""))
            .context("Failed to decode CSR PEM base64")?
    } else {
        csr_data
    };

    // Parse CSR DER with x509-parser
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
            .map_err(|e| anyhow!("Failed to parse CSR DER: {e}"))?;

    let mut domains: Vec<String> = Vec::new();

    // Extract Common Name from subject
    let subject = &csr.certification_request_info.subject;
    for attr in subject.iter_attributes() {
        if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
            if let Ok(value) = attr.attr_value().as_str() {
                domains.push(value.to_string());
            }
        }
    }

    // Extract Subject Alternative Names from extensions
    if let Some(extensions) = csr.requested_extensions() {
        for ext in extensions {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    if let GeneralName::DNSName(d) = name {
                        let d = d.to_string();
                        if !domains.contains(&d) {
                            domains.push(d);
                        }
                    }
                }
            }
        }
    }

    if domains.is_empty() {
        bail!("No domains found in CSR");
    }

    info!("Found domains: {}", domains.join(", "));
    Ok(domains)
}

// ---------------------------------------------------------------------------
// Get CSR in DER format (for order finalization)
// Replaces: openssl req -in csr -outform DER
// ---------------------------------------------------------------------------

fn get_csr_der(path: &str) -> Result<Vec<u8>> {
    let csr_data = fs::read(path)
        .with_context(|| format!("Error loading CSR file: {path}"))?;

    if csr_data.starts_with(b"-----") {
        let pem_str = std::str::from_utf8(&csr_data).context("CSR PEM is not valid UTF-8")?;
        let base64_body: String = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        Ok(STANDARD
            .decode(&base64_body.replace(&['\n', '\r'][..], ""))
            .context("Failed to decode CSR PEM base64")?)
    } else {
        Ok(csr_data)
    }
}

// ---------------------------------------------------------------------------
// Build HTTP client with optional custom CA bundle
// ---------------------------------------------------------------------------

fn build_http_client(cli: &Cli) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();

    if cli.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        // Support SSL_CERT_FILE env var (for pebble tests) and --ca-bundle flag
        if let Some(ref path) = cli.ca_bundle {
            let cert_pem = fs::read(path)
                .with_context(|| format!("Error reading CA bundle: {path}"))?;
            let cert = reqwest::tls::Certificate::from_pem(&cert_pem)
                .context("Failed to parse CA certificate")?;
            builder = builder.add_root_certificate(cert);
        } else if let Ok(path) = std::env::var("SSL_CERT_FILE") {
            if let Ok(cert_pem) = fs::read(&path) {
                if let Ok(cert) = reqwest::tls::Certificate::from_pem(&cert_pem) {
                    builder = builder.add_root_certificate(cert);
                }
            }
        }
    }

    builder.build().context("Failed to create HTTP client")
}

// ---------------------------------------------------------------------------
// Main ACME flow
// ---------------------------------------------------------------------------

async fn get_crt(
    cli: &Cli,
    signing_key: &SigningKey,
    domains: &[String],
) -> Result<String> {
    let client = build_http_client(cli)?;

    // Compute JWK thumbprint (RFC 7638) — canonical JSON with sorted keys
    let thumbprint = {
        let jwk = signing_key.jwk();
        // Use serde_json to produce sorted, compact JSON
        let canonical = canonical_jwk_json(jwk)?;
        b64(&Sha256::digest(canonical.as_bytes()))
    };

    // Determine directory URL
    let dir_url = if let Some(ref ca) = cli.ca {
        info!("Using CA: {ca} (deprecated, use --directory-url instead)");
        format!("{ca}/directory")
    } else {
        cli.directory_url.clone()
    };

    // Get ACME directory
    info!("Getting directory...");
    let (dir_json, status, _) =
        do_request(&client, &dir_url, None, "Error getting directory").await?;
    if !status.is_success() {
        bail!("Error getting directory: HTTP {status}\n{dir_json}");
    }
    let directory: Directory =
        serde_json::from_value(dir_json).context("Failed to parse directory response")?;
    info!("Directory found!");

    // Register account
    info!("Registering account...");
    let mut acct_location: Option<String> = None;

    // External Account Binding (RFC 8555 §7.3.4)
    let eab = if let (Some(ref kid), Some(ref hmac_key)) = (&cli.eab_kid, &cli.eab_hmac_key) {
        let jwk_json = serde_json::to_string(signing_key.jwk())?;
        let eab_protected = serde_json::json!({
            "alg": "HS256",
            "kid": kid,
            "url": directory.new_account,
        });
        let protected64 = b64(serde_json::to_string(&eab_protected)?.as_bytes());
        let payload64 = b64(jwk_json.as_bytes());
        let signing_input = format!("{protected64}.{payload64}");

        let decoded_key = URL_SAFE_NO_PAD.decode(hmac_key.as_bytes())
            .context("EAB HMAC key is not valid base64url")?;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(&decoded_key)
            .context("EAB HMAC key invalid")?;
        mac.update(signing_input.as_bytes());
        let sig = mac.finalize().into_bytes();

        Some(serde_json::json!({
            "protected": protected64,
            "payload": payload64,
            "signature": b64(&sig),
        }))
    } else {
        None
    };

    let mut reg_payload = if let Some(ref contact) = cli.contact {
        serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": contact,
        })
    } else {
        serde_json::json!({
            "termsOfServiceAgreed": true,
        })
    };

    if let Some(ref eab_obj) = eab {
        reg_payload["externalAccountBinding"] = eab_obj.clone();
    }

    let (_account, code, headers) = send_signed_request(
        &client,
        &directory.new_account,
        Some(&reg_payload),
        "Error registering account",
        signing_key,
        &acct_location,
        &directory,
    )
    .await?;

    if let Some(loc) = headers.get("Location") {
        acct_location = Some(loc.to_str()?.to_string());
    }

    let acct_id = acct_location.as_deref().unwrap_or("unknown");
    if code == reqwest::StatusCode::CREATED {
        info!("Registered! Account ID: {acct_id}");
    } else {
        info!("Already registered! Account ID: {acct_id}");
    }

    // Update contact if provided
    if cli.contact.is_some() {
        if let Some(ref loc) = acct_location {
            let contact_payload = serde_json::json!({
                "contact": cli.contact.as_ref().unwrap(),
            });
            let (account_resp, _, _) = send_signed_request(
                &client,
                loc,
                Some(&contact_payload),
                "Error updating contact details",
                signing_key,
                &acct_location,
                &directory,
            )
            .await?;
            if let Some(contacts) = account_resp.get("contact").and_then(|c| c.as_array()) {
                let contact_lines: Vec<String> = contacts
                    .iter()
                    .filter_map(|c| c.as_str().map(|s| s.to_string()))
                    .collect();
                info!(
                    "Updated contact details:\n{}",
                    contact_lines.join("\n")
                );
            }
        }
    }

    // Create new order
    info!("Creating new order...");
    let identifiers: Vec<serde_json::Value> = domains
        .iter()
        .map(|d| serde_json::json!({"type": "dns", "value": d}))
        .collect();
    let order_payload = serde_json::json!({"identifiers": identifiers});

    let (order, _, headers) = send_signed_request(
        &client,
        &directory.new_order,
        Some(&order_payload),
        "Error creating new order",
        signing_key,
        &acct_location,
        &directory,
    )
    .await?;

    let order_location = headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Missing order Location header"))?;

    info!("Order created!");

    // Process authorizations
    let authorizations: Vec<String> = order["authorizations"]
        .as_array()
        .ok_or_else(|| anyhow!("No authorizations in order"))?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    for auth_url in &authorizations {
        let (authorization, _, _) = send_signed_request(
            &client,
            auth_url,
            None,
            "Error getting challenges",
            signing_key,
            &acct_location,
            &directory,
        )
        .await?;

        let domain = authorization["identifier"]["value"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        // Skip if already valid
        if authorization["status"].as_str() == Some("valid") {
            info!("Already verified: {domain}, skipping...");
            continue;
        }
        info!("Verifying {domain}...");

        let challenge_type = &cli.challenge_type;

        // Find matching challenge
        let challenges = authorization["challenges"]
            .as_array()
            .ok_or_else(|| anyhow!("No challenges for {domain}"))?;
        let challenge = challenges
            .iter()
            .find(|c| c["type"].as_str() == Some(challenge_type))
            .ok_or_else(|| anyhow!("No {challenge_type} challenge for {domain}"))?;

        let token = challenge["token"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing challenge token"))?;
        let cleaned_token: String = token
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let keyauthorization = format!("{cleaned_token}.{thumbprint}");

        if challenge_type == "http-01" {
            // HTTP-01: write file to .well-known/acme-challenge/
            let wellknown_path = Path::new(&cli.acme_dir).join(&cleaned_token);
            fs::write(&wellknown_path, &keyauthorization)
                .with_context(|| format!("Failed to write challenge file: {:?}", wellknown_path))?;

            if !cli.disable_check {
                let check_port_str = cli
                    .check_port
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default();
                let wellknown_url = format!(
                    "http://{domain}{check_port_str}/.well-known/acme-challenge/{cleaned_token}"
                );
                match client
                    .get(&wellknown_url)
                    .header("User-Agent", USER_AGENT)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let body_text = resp.text().await.unwrap_or_default();
                        if body_text != keyauthorization {
                            let _ = fs::remove_file(&wellknown_path);
                            bail!(
                                "Wrote file to {}, but couldn't download {}: unexpected content",
                                wellknown_path.display(),
                                wellknown_url
                            );
                        }
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&wellknown_path);
                        bail!(
                            "Wrote file to {}, but couldn't download {}: {}",
                            wellknown_path.display(),
                            wellknown_url,
                            e
                        );
                    }
                }
            }
        } else if challenge_type == "dns-01" {
            let txt_value = dns::dns_txt_value(&cleaned_token, &thumbprint);
            dns::create_provider(&cli.dns_provider)?.present(&domain, &txt_value)?;
        } else {
            bail!("Unsupported challenge type: {challenge_type}");
        }

        // Submit challenge
        send_signed_request(
            &client,
            challenge["url"].as_str().unwrap_or(""),
            Some(&serde_json::json!({})),
            &format!("Error submitting challenge for {domain}"),
            signing_key,
            &acct_location,
            &directory,
        )
        .await?;

        // Wait for challenge to complete
        let authorization = poll_until_not(
            &client,
            auth_url,
            &["pending"],
            &format!("Error checking challenge status for {domain}"),
            signing_key,
            &acct_location,
            &directory,
        )
        .await?;

        // Clean up
        if challenge_type == "http-01" {
            let wellknown_path = Path::new(&cli.acme_dir).join(&cleaned_token);
            let _ = fs::remove_file(&wellknown_path);
        } else if challenge_type == "dns-01" {
            let txt_value = dns::dns_txt_value(&cleaned_token, &thumbprint);
            let _ = dns::create_provider(&cli.dns_provider)
                .and_then(|p| p.cleanup(&domain, &txt_value));
        }

        if authorization["status"].as_str() != Some("valid") {
            bail!("Challenge did not pass for {domain}: {authorization}");
        }
        info!("{domain} verified!");
    }

    // Finalize the order with CSR
    info!("Signing certificate...");
    let csr_der = get_csr_der(&cli.csr)?;
    let finalize_payload = serde_json::json!({
        "csr": b64(&csr_der),
    });

    let finalize_url = order["finalize"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing finalize URL in order"))?;
    send_signed_request(
        &client,
        finalize_url,
        Some(&finalize_payload),
        "Error finalizing order",
        signing_key,
        &acct_location,
        &directory,
    )
    .await?;

    // Poll order status
    let order = poll_until_not(
        &client,
        &order_location,
        &["pending", "processing"],
        "Error checking order status",
        signing_key,
        &acct_location,
        &directory,
    )
    .await?;

    if order["status"].as_str() != Some("valid") {
        bail!("Order failed: {order}");
    }

    // Download certificate (ACME returns PEM, not JSON)
    let cert_url = order["certificate"]
        .as_str()
        .ok_or_else(|| anyhow!("No certificate URL in order"))?;

    let certificate_pem = download_certificate(
        &client,
        cert_url,
        signing_key,
        &acct_location,
        &directory,
    )
    .await?;

    info!("Certificate signed!");
    Ok(certificate_pem)
}

// ---------------------------------------------------------------------------
// Download certificate (ACME returns PEM, not JSON)
// ---------------------------------------------------------------------------

async fn download_certificate(
    client: &reqwest::Client,
    url: &str,
    signing_key: &SigningKey,
    acct_location: &Option<String>,
    directory: &Directory,
) -> Result<String> {
    // Build a signed POST with empty payload (Accept: application/pem-certificate-chain)
    let payload64 = "";
    let nonce_resp = do_request(client, &directory.new_nonce, None, "Error getting nonce").await?;
    let nonce = nonce_resp
        .2
        .get("Replay-Nonce")
        .ok_or_else(|| anyhow!("Missing Replay-Nonce header"))?
        .to_str()?
        .to_string();

    let alg = signing_key.alg();
    let jwk = signing_key.jwk();

    let mut protected: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    protected.insert("url".into(), serde_json::Value::String(url.to_string()));
    protected.insert("alg".into(), serde_json::Value::String(alg.to_string()));
    protected.insert("nonce".into(), serde_json::Value::String(nonce));
    if let Some(ref kid) = acct_location {
        protected.insert("kid".into(), serde_json::Value::String(kid.clone()));
    } else {
        protected.insert("jwk".into(), jwk.clone());
    }

    let protected64 = b64(serde_json::to_string(&protected).unwrap().as_bytes());
    let signing_input = format!("{protected64}.{payload64}");
    let signature = signing_key.sign(signing_input.as_bytes())?;

    let jws = JwsBody {
        protected: protected64,
        payload: payload64.to_string(),
        signature: b64(&signature),
    };

    let resp = client
        .post(url)
        .header("Content-Type", "application/jose+json")
        .header("Accept", "application/pem-certificate-chain")
        .header("User-Agent", USER_AGENT)
        .body(serde_json::to_vec(&jws)?)
        .send()
        .await
        .context("Certificate download failed")?;

    let status = resp.status();
    if !status.is_success() {
        bail!("Certificate download failed: HTTP {status}");
    }

    let body = resp.text().await.context("Failed to read certificate response")?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Configure logging
    let log_level = if cli.quiet {
        LevelFilter::Error
    } else {
        LevelFilter::Info
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_target(false)
        .format_timestamp(None)
        .init();

    // Parse account key — supports RSA (PKCS#1/PKCS#8), ECDSA P-256/P-384 (SEC1/PKCS#8)
    let signing_key = parse_account_key(&cli.account_key)?;

    // Parse CSR (replaces: openssl req -in csr -noout -text)
    let domains = parse_csr(&cli.csr)?;

    // Wildcard domains require dns-01 challenge (RFC 8555 §8.4)
    let has_wildcard = domains.iter().any(|d| d.starts_with("*."));
    if has_wildcard && cli.challenge_type != "dns-01" {
        bail!(
            "Wildcard domain requires --challenge-type dns-01.\n\
             Wildcard domains found: {}\n\
             Add: --challenge-type dns-01 [--dns-provider <provider>]",
            domains.iter().filter(|d| d.starts_with("*.")).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
    }

    // Run ACME flow
    let certificate = get_crt(&cli, &signing_key, &domains).await?;

    // Output certificate to stdout
    print!("{certificate}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b64() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg");
        assert_eq!(b64(b"fo"), "Zm8");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foob"), "Zm9vYg");
        assert_eq!(b64(b"fooba"), "Zm9vYmE");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_canonical_jwk_json_rsa() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "sG37a3H...",
            "e": "AQAB",
        });
        let canonical = canonical_jwk_json(&jwk).unwrap();
        assert_eq!(canonical, r#"{"e":"AQAB","kty":"RSA","n":"sG37a3H..."}"#);
    }

    #[test]
    fn test_canonical_jwk_json_ec() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        });
        let canonical = canonical_jwk_json(&jwk).unwrap();
        assert!(canonical.starts_with(r#"{"crv":"P-256","#));
        assert!(canonical.contains(r#""kty":"EC""#));
        assert!(!canonical.contains(' '));
    }

    #[test]
    fn test_extract_pem_blocks_single() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg...\n-----END RSA PRIVATE KEY-----\n";
        let blocks = extract_pem_blocks(pem);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].starts_with("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn test_extract_pem_blocks_multi() {
        let pem = concat!(
            "-----BEGIN EC PARAMETERS-----\nBw==\n-----END EC PARAMETERS-----\n",
            "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE...\n-----END EC PRIVATE KEY-----\n"
        );
        let blocks = extract_pem_blocks(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("EC PARAMETERS"));
        assert!(blocks[1].contains("EC PRIVATE KEY"));
    }

    #[test]
    fn test_extract_pem_blocks_no_markers() {
        let pem = "not a pem file\njust some text\n";
        let blocks = extract_pem_blocks(pem);
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn test_parse_account_key_rsa() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("rsa.key");
        std::process::Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&key_path)
            .arg("2048")
            .output()
            .unwrap();
        let result = parse_account_key(key_path.to_str().unwrap());
        assert!(result.is_ok());
        let sk = result.unwrap();
        assert_eq!(sk.alg(), "RS256");
    }

    #[test]
    #[cfg(not(windows))]
    fn test_parse_account_key_ec_p256() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ec.key");
        std::process::Command::new("openssl")
            .args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"])
            .arg(&key_path)
            .output()
            .unwrap();
        let result = parse_account_key(key_path.to_str().unwrap());
        assert!(result.is_ok(), "Error: {:?}", result.err());
        let sk = result.unwrap();
        assert_eq!(sk.alg(), "ES256");
    }

    #[test]
    #[cfg(not(windows))]
    fn test_parse_account_key_ec_p384_sec1() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ec384.key");
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "openssl ecparam -genkey -name secp384r1 2>/dev/null > {}",
                key_path.display()
            ))
            .output()
            .unwrap();
        let result = parse_account_key(key_path.to_str().unwrap());
        assert!(result.is_ok(), "Error: {:?}", result.err());
        let sk = result.unwrap();
        assert_eq!(sk.alg(), "ES384");
    }

    #[test]
    fn test_parse_account_key_missing() {
        assert!(parse_account_key("/nonexistent.key").is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_signing_roundtrip_rsa() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("rsa.key");
        std::process::Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&key_path)
            .arg("2048")
            .output()
            .unwrap();
        let sk = parse_account_key(key_path.to_str().unwrap()).unwrap();
        let sig = sk.sign(b"test signing data").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_signing_roundtrip_ecdsa() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ec.key");
        std::process::Command::new("openssl")
            .args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"])
            .arg(&key_path)
            .output()
            .unwrap();
        let sk = parse_account_key(key_path.to_str().unwrap()).unwrap();
        let sig = sk.sign(b"test signing data").unwrap();
        assert!(!sig.is_empty());
    }
}
