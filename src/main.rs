use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::{Parser, Subcommand, ValueHint};
use log::{debug, info, LevelFilter};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::SecretKey as P256SecretKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p384::SecretKey as P384SecretKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use std::io::{BufWriter, Write};
use std::sync::{Mutex, OnceLock};

/// Request/response log file (initialized once in main)
static LOG_FILE: OnceLock<Mutex<Option<BufWriter<std::fs::File>>>> = OnceLock::new();
/// Log verbosity level (1 = request line, 2 = request + body)
static LOG_LEVEL: OnceLock<u8> = OnceLock::new();

/// Initialize log file from --log and --log-level flags
fn init_log(log_path: Option<&str>, log_level: u8) -> Result<()> {
    LOG_LEVEL.set(log_level).ok();
    if let Some(path) = log_path {
        let f = std::fs::File::create(path)
            .with_context(|| format!("Failed to create log file: {path}"))?;
        LOG_FILE.set(Mutex::new(Some(BufWriter::new(f)))).ok();
    }
    Ok(())
}

/// Format a response header for diagnostic output. Distinguishes three cases:
///   - header absent: "<missing>"
///   - header present, valid UTF-8: the value
///   - header present, non-UTF-8 bytes: "<binary N bytes>"
fn header_diag(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    match headers.get(name) {
        None => "<missing>".to_string(),
        Some(v) => v
            .to_str()
            .map(String::from)
            .unwrap_or_else(|_| format!("<binary {} bytes>", v.len())),
    }
}

/// RAII guard for a standalone challenge server (TLS-ALPN-01 or HTTP-01
/// standalone). Dropping the guard aborts the spawned listener task.
///
/// This is critical: dropping a `tokio::task::JoinHandle` does NOT abort the
/// underlying task — it only severs the result channel. The listener keeps
/// running and holding the port. A plain `Option<JoinHandle>` with the
/// underscore-prefix binding pattern used in earlier versions of this code
/// silently leaked the port on every iteration.
struct StandaloneServerGuard(Option<tokio::task::JoinHandle<()>>);

impl Drop for StandaloneServerGuard {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

macro_rules! log_request {
    ($($arg:tt)*) => {{
        if let Some(mutex) = LOG_FILE.get() {
            if let Ok(mut guard) = mutex.lock() {
                if let Some(ref mut writer) = *guard {
                    let _ = writeln!(writer, $($arg)*);
                    let _ = writer.flush();
                }
            }
        }
    }};
}

const DEFAULT_SERVER: &str = "letsencrypt";
const USER_AGENT: &str = concat!("acme-tiny-rs/", env!("CARGO_PKG_VERSION"));

mod ca;
mod challenge;
mod commands;
mod dns;
mod hook;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "acme-tiny-rs",
    about = concat!("A tiny ACME client to issue and renew TLS certs from Let's Encrypt — v",
        env!("CARGO_PKG_VERSION"),
        " (", env!("GIT_HASH"), " ", env!("BUILD_TIME"), ")"),
    after_help = "Example:\n  acme-tiny-rs --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/challenges/ > signed_chain.crt"
)]
struct Cli {
    /// Path to your Let's Encrypt account private key
    #[arg(long = "account-key", value_hint = ValueHint::FilePath)]
    account_key: Option<String>,

    /// Path to your certificate signing request (CSR)
    #[arg(long = "csr", value_hint = ValueHint::FilePath)]
    csr: Option<String>,

    /// Path to the .well-known/acme-challenge/ directory
    #[arg(long = "acme-dir")]
    acme_dir: Option<String>,

    /// Suppress output except for errors
    #[arg(long = "quiet")]
    quiet: bool,

    /// Disable checking if the challenge file is hosted correctly
    #[arg(long = "disable-check")]
    disable_check: bool,

    /// ACME CA server — preset name or full URL (default: letsencrypt)
    ///
    /// Preset names: letsencrypt, letsencrypt-staging, zerossl,
    ///               sslcom, sslcom-ecc, google, googletest, actalis, step, pebble, pebble-eab
    ///
    /// Or provide a full URL: https://my-ca.example.com/directory
    #[arg(long = "server", default_value = DEFAULT_SERVER)]
    server: String,

    /// Certificate authority directory URL (overrides --server)
    #[arg(long = "directory-url")]
    directory_url: Option<String>,

    /// List all known CA presets and exit
    #[arg(long = "list-ca")]
    list_ca: bool,

    /// DEPRECATED! Use --server or --directory-url instead
    #[arg(long = "ca")]
    ca: Option<String>,

    /// Contact details (e.g. mailto:aaa@bbb.com) for your account-key
    #[arg(long = "contact", num_args = 0..)]
    contact: Option<Vec<String>>,

    /// What port to use when self-checking the challenge file
    #[arg(long = "check-port")]
    check_port: Option<u16>,

    /// Challenge type: http-01 (default), dns-01, tls-alpn-01, dns-persist-01, or dns-account-01 (draft)
    #[arg(long = "challenge-type", default_value = "http-01")]
    challenge_type: String,

    /// Use built-in HTTP server instead of writing challenge files (standalone mode)
    #[arg(long = "standalone")]
    standalone: bool,

    /// HTTP-01 standalone listen port (default: 80)
    #[arg(long = "http-01-port", visible_alias = "httpport")]
    http01_port: Option<u16>,

    /// TLS-ALPN-01 standalone listen port (default: 443)
    #[arg(long = "tls-alpn-01-port", visible_alias = "tlsport")]
    tls_alpn01_port: Option<u16>,

    /// DNS provider for dns-01 challenge: exec (script-based), manual (interactive),
    /// cloudflare (cf), alibaba (ali), aws (route53), azure, acmedns, acmeproxy,
    /// huaweicloud (huawei), duckdns, linode (linode_v4), vultr, namecheap,
    /// desec, gandi, namesilo, porkbun, bunny (bunnycdn), ionos,
    /// tencent (tencentcloud), jdcloud (jd), netlify,
    /// gcloud (google), digitalocean (do, dgon), ovh, dnsimple
    #[arg(long = "dns-provider", default_value = "manual")]
    dns_provider: String,

    /// Per-domain DNS challenge alias (target domain for CNAME delegation)
    #[arg(long = "challenge-alias")]
    challenge_alias: Option<String>,

    /// EAB Key Identifier (for External Account Binding)
    #[arg(long = "eab-kid")]
    eab_kid: Option<String>,

    /// EAB HMAC Key (base64url-encoded, for External Account Binding)
    #[arg(long = "eab-hmac-key")]
    eab_hmac_key: Option<String>,

    /// HMAC algorithm for EAB (HS256, HS384, HS512) [default: HS256]
    #[arg(long = "eab-hmac-alg", default_value = "HS256")]
    eab_hmac_alg: String,

    /// Agree to the CA's Terms of Service [default: true]
    #[arg(long = "agree-tos", default_value_t = true)]
    agree_tos: bool,

    /// ACME profile name for the new order (e.g., tlsserver, shortlived)
    #[arg(short = 'P', long = "profile")]
    profile: Option<String>,

    /// Force issuance (skip ARI/renew-before check). Default true for backward compatibility.
    #[arg(
        long = "force",
        visible_alias = "force-renewal",
        default_value_t = true
    )]
    force: bool,

    /// Check ARI renewal window before issuing (requires --existing-cert)
    #[arg(long = "ari")]
    ari: bool,

    /// Write request/response to log file (requires --output)
    #[arg(long = "log", value_hint = ValueHint::FilePath, requires = "output")]
    log: Option<String>,

    /// Log verbosity: 1 = request line only, 2 = request + body (default: 1)
    #[arg(long = "log-level", default_value = "1")]
    log_level: u8,

    /// Skip issuance if --cert is valid for more than N days (acme.sh: Le_RenewalDays, certbot: renew_before_expiry)
    #[arg(long = "renew-before", value_name = "DAYS", requires = "existing_cert")]
    min_days_left: Option<u64>,

    /// Path to existing certificate for ARI check and replaces field
    #[arg(long = "existing-cert", visible_alias = "cert", value_hint = ValueHint::FilePath)]
    existing_cert: Option<String>,

    /// Write certificate to file instead of stdout
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// TCP connect timeout in seconds (system default if unset)
    #[arg(long = "connect-timeout")]
    connect_timeout: Option<u64>,

    /// Per-request timeout in seconds (system default if unset)
    #[arg(long = "timeout")]
    timeout: Option<u64>,

    // ---- Hooks (acme.sh compatible) ----
    /// Command or script to run before obtaining any certificates
    #[arg(long = "pre-hook")]
    pre_hook: Option<String>,

    /// Command or script to run after attempting obtain/renew
    #[arg(long = "post-hook")]
    post_hook: Option<String>,

    /// Command or script to run after each successfully renewed certificate
    #[arg(long = "renew-hook")]
    renew_hook: Option<String>,

    /// Command or script to run after certificate issuance to deploy (requires --output)
    #[arg(long = "deploy-hook", requires = "output")]
    deploy_hook: Option<String>,

    /// Command or script to run for notifications
    #[arg(long = "notify-hook")]
    notify_hook: Option<String>,

    /// Path to additional CA certificate bundle for TLS verification
    #[arg(long = "ca-bundle", value_hint = ValueHint::FilePath)]
    ca_bundle: Option<String>,

    /// Disable TLS certificate verification (testing only)
    #[arg(short = 'k', long = "insecure", hide = true)]
    insecure: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Resolve the directory URL from CLI args.
/// Priority: --directory-url > --server (preset or URL) > --ca (deprecated)
fn resolve_directory_url(cli: &Cli) -> Result<String> {
    if let Some(ref url) = cli.directory_url {
        return Ok(url.clone());
    }
    // --server can be a preset name or a full URL
    let resolved = ca::resolve(&cli.server)?;
    Ok(resolved.directory_url())
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
enum AccountAction {
    /// Display account details
    Show,
    /// Update account contact information
    Update {
        /// Email address(es) for account notifications
        #[arg(short = 'm')]
        email: Option<Vec<String>>,
    },
    /// Register a new ACME account
    Register {
        /// Email address(es) for account notifications
        #[arg(short = 'm')]
        email: Option<Vec<String>>,
        /// Agree to the CA's Terms of Service
        #[arg(long = "agree-tos", default_value_t = true)]
        agree_tos: bool,
        /// EAB Key Identifier (for External Account Binding)
        #[arg(long = "eab-kid")]
        eab_kid: Option<String>,
        /// EAB HMAC Key (base64url-encoded)
        #[arg(long = "eab-hmac-key")]
        eab_hmac_key: Option<String>,
        /// HMAC algorithm for EAB (HS256, HS384, HS512)
        #[arg(long = "eab-hmac-alg", default_value = "HS256")]
        eab_hmac_alg: String,
    },
    /// Deactivate (unregister) an ACME account
    Unregister,
    /// Change account key (RFC 8555 §7.3.5 key rollover)
    ChangeKey {
        /// Path to the new account private key
        #[arg(long = "new-key", value_hint = ValueHint::FilePath)]
        new_key: String,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// ARI renewal info check for a certificate
    Ari {
        #[arg(long = "cert")]
        cert: String,
        #[arg(long = "directory-url")]
        directory_url: Option<String>,
        #[arg(long = "server", default_value = DEFAULT_SERVER)]
        server: String,
        /// Disable TLS certificate verification (testing only)
        #[arg(short = 'k', long = "insecure", hide = true)]
        insecure: bool,
        /// Verbose diagnostic output to stderr (-v or -vv for more detail)
        #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
        verbose: u8,
    },
    /// List all known ACME CA presets
    ListCa {
        /// Output as JSON instead of table
        #[arg(long = "json")]
        json: bool,
        /// Suppress table header and footer
        #[arg(long = "no-header")]
        no_header: bool,
    },
    /// Inspect ACME CA directory (fetch raw JSON)
    InspectCa {
        /// ACME server preset name or URL
        #[arg(long = "server", default_value = DEFAULT_SERVER)]
        server: String,
        /// Verbose output (-v, -vv, -vvv)
        #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
        verbose: u8,
        /// Disable TLS certificate verification (testing only)
        #[arg(short = 'k', long = "insecure", hide = true)]
        insecure: bool,
    },
    /// Inspect TLS certificate details (table or JSON)
    Inspect {
        /// Domain(s) to check (host[:port] format, port defaults to 443)
        #[arg(short = 'd', long = "domain", required = true, num_args = 1..)]
        domains: Vec<String>,
        /// Default port when not specified in domain
        #[arg(long = "port", default_value_t = 443)]
        port: u16,
        /// Output as JSON instead of table
        #[arg(long = "json")]
        json: bool,
        /// Accept self-signed certificates (-k like curl)
        #[arg(short = 'k', long = "insecure")]
        insecure: bool,
        /// Lint certificate for RFC 5280 compliance issues
        #[arg(long = "lint")]
        lint: bool,
        /// Suppress table header and separator rows
        #[arg(long = "no-header")]
        no_header: bool,
    },
    /// Dump TLS certificate chain (like openssl s_client -showcerts)
    Dump {
        /// Domain to connect to (host[:port])
        #[arg()]
        domain: String,
        /// Default port when not specified in domain
        #[arg(long = "port", default_value_t = 443)]
        port: u16,
        /// Write output to file instead of stdout
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
        /// Output format
        #[arg(long = "format", default_value = "pem")]
        format: commands::dump::DumpFormat,
        /// Accept self-signed certificates (-k like curl)
        #[arg(short = 'k', long = "insecure")]
        insecure: bool,
    },
    /// Revoke a certificate (RFC 8555 §7.6)
    Revoke {
        /// Path to the certificate (PEM) to revoke
        #[arg(long = "cert")]
        cert: String,
        /// Path to the ACME account private key
        #[arg(long = "account-key")]
        account_key: String,
        /// ACME directory URL (overrides --server)
        #[arg(long = "directory-url")]
        directory_url: Option<String>,
        /// ACME server preset name or URL
        #[arg(long = "server", default_value = DEFAULT_SERVER)]
        server: String,
        /// Revocation reason code (0-10 per RFC 5280)
        #[arg(long = "reason")]
        reason: Option<u32>,
        /// Path to CA bundle for TLS verification
        #[arg(long = "ca-bundle")]
        ca_bundle: Option<String>,
        /// Disable TLS certificate verification (testing only)
        #[arg(short = 'k', long = "insecure", hide = true)]
        insecure: bool,
    },
    /// Manage ACME account (show, update, register, unregister)
    #[command(alias = "a")]
    Account {
        /// Verbose output (-v, -vv, -vvv)
        #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
        verbose: u8,
        /// ACME server preset name or URL
        #[arg(long = "server", default_value = DEFAULT_SERVER, global = true)]
        server: String,
        /// ACME directory URL (overrides --server)
        #[arg(long = "directory-url", global = true)]
        directory_url: Option<String>,
        /// Disable TLS certificate verification (testing only)
        #[arg(short = 'k', long = "insecure", hide = true, global = true)]
        insecure: bool,
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Generate shell completion script (bash, zsh, fish)
    Completions {
        /// Shell to generate completions for
        #[arg(value_name = "SHELL")]
        shell: String,
    },
    /// Output JWK thumbprint (RFC 7638) for stateless HTTP-01 / dns-account-01
    Thumbprint {
        /// Path to the ACME account private key
        #[arg(long = "account-key")]
        account_key: String,
    },
    /// Print version information
    Version,
}

// ---------------------------------------------------------------------------
// JSON types for ACME protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Directory {
    #[serde(rename = "newNonce")]
    pub(crate) new_nonce: String,
    #[serde(rename = "newAccount")]
    pub(crate) new_account: String,
    #[serde(rename = "newOrder")]
    pub(crate) new_order: String,
    #[serde(rename = "renewalInfo")]
    pub(crate) renewal_info: Option<String>,
    #[serde(rename = "keyChange")]
    pub(crate) key_change: Option<String>,
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

pub(crate) enum SigningKey {
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
    Ed25519 {
        key: ed25519_dalek::SigningKey,
        jwk: serde_json::Value,
    },
}

impl SigningKey {
    fn jwk(&self) -> &serde_json::Value {
        match self {
            SigningKey::Rsa { jwk, .. }
            | SigningKey::EcdsaP256 { jwk, .. }
            | SigningKey::EcdsaP384 { jwk, .. }
            | SigningKey::Ed25519 { jwk, .. } => jwk,
        }
    }

    fn alg(&self) -> &'static str {
        match self {
            SigningKey::Rsa { .. } => "RS256",
            SigningKey::EcdsaP256 { .. } => "ES256",
            SigningKey::EcdsaP384 { .. } => "ES384",
            SigningKey::Ed25519 { .. } => "EdDSA",
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
            SigningKey::Ed25519 { key, .. } => {
                use ed25519_dalek::Signer;
                Ok(key.sign(data).to_vec())
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

pub(crate) async fn do_request(
    client: &reqwest::Client,
    url: &str,
    data: Option<Vec<u8>>,
    err_msg: &str,
) -> Result<(
    serde_json::Value,
    reqwest::StatusCode,
    reqwest::header::HeaderMap,
)> {
    let data_str = data
        .as_ref()
        .map(|d| String::from_utf8_lossy(d).to_string());
    let method = if data.is_some() { "POST" } else { "GET" };

    // Log request
    if let Some(ref body) = data_str {
        log_request!("-> {} {} {}", method, url, body);
    } else {
        log_request!("-> {} {}", method, url);
    }

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

    // Log response
    log_request!("<- {} {} {}", status.as_u16(), url, body_text);

    // Validate HTTP status (ACME success codes: 200, 201, 204)
    if status != reqwest::StatusCode::OK
        && status != reqwest::StatusCode::CREATED
        && status != reqwest::StatusCode::NO_CONTENT
        && !(status == reqwest::StatusCode::BAD_REQUEST
            && (json.get("type").and_then(|t| t.as_str())
                == Some("urn:ietf:params:acme:error:badNonce")))
        && !(status == reqwest::StatusCode::CONFLICT
            && (json.get("type").and_then(|t| t.as_str())
                == Some("urn:ietf:params:acme:error:alreadyReplaced")))
    {
        bail!(
            "{err_msg}:\nUrl: {url}\nData: {}\nResponse Code: {status}\nContent-Type: {}\nLocation: {}\nReplay-Nonce: {}\nResponse: {json}",
            data_str.as_deref().unwrap_or("None"),
            header_diag(&headers, "Content-Type"),
            header_diag(&headers, "Location"),
            header_diag(&headers, "Replay-Nonce"),
        );
    }

    Ok((json, status, headers))
}

// ---------------------------------------------------------------------------
// Signed request helper (JWS with RS256)
// ---------------------------------------------------------------------------

pub(crate) async fn get_nonce(client: &reqwest::Client, directory: &Directory) -> Result<String> {
    let (_, _, headers) = do_request(client, &directory.new_nonce, None, "nonce").await?;
    Ok(headers
        .get("Replay-Nonce")
        .ok_or_else(|| anyhow!("Missing Replay-Nonce header"))?
        .to_str()?
        .to_string())
}

pub(crate) async fn send_signed_request(
    client: &reqwest::Client,
    url: &str,
    payload: Option<&serde_json::Value>,
    err_msg: &str,
    signing_key: &SigningKey,
    acct_location: &Option<String>,
    directory: &Directory,
) -> Result<(
    serde_json::Value,
    reqwest::StatusCode,
    reqwest::header::HeaderMap,
)> {
    send_signed_request_inner(
        client,
        url,
        payload,
        err_msg,
        signing_key,
        acct_location,
        directory,
        0,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_signed_request_inner(
    client: &reqwest::Client,
    url: &str,
    payload: Option<&serde_json::Value>,
    err_msg: &str,
    signing_key: &SigningKey,
    acct_location: &Option<String>,
    directory: &Directory,
    depth: u32,
) -> Result<(
    serde_json::Value,
    reqwest::StatusCode,
    reqwest::header::HeaderMap,
)> {
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

    // Handle badNonce retry (RFC 8555 §6.5: client SHOULD use a fresh nonce
    // on each request). When the CA evicts a nonce from its cache between our
    // HEAD and POST we can race and lose. Limit retries and back off so we
    // don't hammer the CA while it's regenerating nonces.
    if result.1 == reqwest::StatusCode::BAD_REQUEST
        && (result.0.get("type").and_then(|t| t.as_str())
            == Some("urn:ietf:params:acme:error:badNonce"))
    {
        const MAX_NONCE_RETRIES: u32 = 5;
        if depth >= MAX_NONCE_RETRIES {
            bail!(
                "Too many badNonce retries ({MAX_NONCE_RETRIES}) — server may be \
                 misconfigured or overloaded; giving up"
            );
        }
        // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms.
        let delay = Duration::from_millis(100u64 << depth);
        debug!(
            "badNonce on {} (depth {}), retrying after {}ms",
            url,
            depth,
            delay.as_millis()
        );
        tokio::time::sleep(delay).await;
        return Box::pin(send_signed_request_inner(
            client,
            url,
            payload,
            err_msg,
            signing_key,
            acct_location,
            directory,
            depth + 1,
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
    let mut poll_count: u32 = 0;

    loop {
        if start.elapsed() > timeout {
            bail!("Polling timeout after {poll_count} iterations");
        }
        if !first {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        first = false;
        poll_count += 1;

        let (res, _, _) = send_signed_request(
            client,
            url,
            None,
            err_msg,
            signing_key,
            acct_location,
            directory,
        )
        .await?;
        result = res;

        let status = result["status"].as_str().unwrap_or("");
        debug!(
            "Poll {poll_count}: status={status} elapsed={}s",
            start.elapsed().as_secs()
        );
        if !pending_statuses.contains(&status) {
            info!(
                "Poll finished after {poll_count} iterations, final status={status} ({}s)",
                start.elapsed().as_secs()
            );
            break;
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Parse RSA account key: extract public key modulus and exponent (native Rust)
// Replaces: openssl rsa -in account.key -noout -text
// ---------------------------------------------------------------------------

pub(crate) fn parse_account_key(path: &str) -> Result<SigningKey> {
    info!("Parsing account key...");
    let pem_data = fs::read_to_string(path)
        .with_context(|| format!("Error reading account key file: {path}"))?;
    parse_account_key_bytes(&pem_data)
}

/// Parse account key from PEM data (used by stdin `-` support).
pub(crate) fn parse_account_key_bytes(pem_data: &str) -> Result<SigningKey> {
    // Detect key type from the PEM block's tag (the part inside BEGIN/END),
    // not from substring matching — substring matches collide with comments
    // and unrelated headers like "OPENSSH PRIVATE KEY".
    let last_tag = primary_pem_tag(pem_data).context("Failed to parse PEM data")?;
    match last_tag.as_str() {
        "RSA PRIVATE KEY" | "RSA PUBLIC KEY" => parse_rsa_key(pem_data),
        "EC PRIVATE KEY" => parse_ec_key(pem_data),
        "PRIVATE KEY" => {
            // PKCS#8 — type unknown until parsed; try each.
            parse_rsa_key(pem_data)
                .or_else(|_| parse_ec_key(pem_data))
                .or_else(|_| parse_ed25519_key(pem_data))
        }
        other => bail!("Unsupported PEM block type: {other}"),
    }
}

/// Return the PEM tag of the last BEGIN/END block in the input. If the input
/// has no recognizable PEM markers, falls back to treating the whole input as
/// one PEM document and reading its tag.
fn primary_pem_tag(pem_data: &str) -> Option<String> {
    let pems = pem::parse_many(pem_data).ok()?;
    pems.last().map(|b| b.tag().to_string())
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
    let last_error =
        || anyhow!("Failed to parse EC private key (tried P-256 and P-384, SEC1 and PKCS#8)");

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
    Ok(SigningKey::EcdsaP256 {
        key: signing_key,
        jwk,
    })
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
    Ok(SigningKey::EcdsaP384 {
        key: signing_key,
        jwk,
    })
}

fn parse_ed25519_key(pem_data: &str) -> Result<SigningKey> {
    let blocks = extract_pem_blocks(pem_data);
    for block in &blocks {
        if let Ok(signing_key) = ed25519_dalek::SigningKey::from_pkcs8_pem(block) {
            let verifying_key = signing_key.verifying_key();
            let jwk = serde_json::json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": b64(verifying_key.as_bytes()),
            });
            return Ok(SigningKey::Ed25519 {
                key: signing_key,
                jwk,
            });
        }
    }
    bail!("Failed to parse Ed25519 private key (PKCS#8)")
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
    let csr_data = fs::read(path).with_context(|| format!("Error loading CSR file: {path}"))?;

    // Try PEM first, then raw DER
    let csr_der = if csr_data.starts_with(b"-----") {
        // PEM format - extract the base64 body
        let pem_str = std::str::from_utf8(&csr_data).context("CSR PEM is not valid UTF-8")?;
        let base64_body: String = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        STANDARD
            .decode(base64_body.replace(&['\n', '\r'][..], ""))
            .context("Failed to decode CSR PEM base64")?
    } else {
        csr_data
    };

    // Parse CSR DER with x509-parser
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
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
                    match name {
                        GeneralName::DNSName(d) => {
                            let d = d.to_string();
                            if !domains.contains(&d) {
                                domains.push(d);
                            }
                        }
                        GeneralName::IPAddress(ip) => {
                            let ip_str = match ip.len() {
                                4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                    ip[0], ip[1], ip[2], ip[3],
                                ))
                                .to_string(),
                                16 => {
                                    let mut bytes = [0u8; 16];
                                    bytes.copy_from_slice(ip);
                                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
                                        .to_string()
                                }
                                _ => continue,
                            };
                            if !domains.contains(&ip_str) {
                                domains.push(ip_str);
                            }
                        }
                        _ => {}
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
    let csr_data = fs::read(path).with_context(|| format!("Error loading CSR file: {path}"))?;

    if csr_data.starts_with(b"-----") {
        let pem_str = std::str::from_utf8(&csr_data).context("CSR PEM is not valid UTF-8")?;
        let base64_body: String = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        Ok(STANDARD
            .decode(base64_body.replace(&['\n', '\r'][..], ""))
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

    if let Some(t) = cli.connect_timeout {
        builder = builder.connect_timeout(Duration::from_secs(t));
    }
    if let Some(t) = cli.timeout {
        builder = builder.timeout(Duration::from_secs(t));
    }

    if cli.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        // Support SSL_CERT_FILE env var (for pebble tests) and --ca-bundle flag
        if let Some(ref path) = cli.ca_bundle {
            let cert_pem =
                fs::read(path).with_context(|| format!("Error reading CA bundle: {path}"))?;
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

async fn get_crt(cli: &Cli, signing_key: &SigningKey, domains: &[String]) -> Result<String> {
    let client = build_http_client(cli)?;

    // Normalize challenge type to lowercase for case-insensitive matching
    let challenge_type = cli.challenge_type.to_lowercase();
    let _challenge_type = challenge_type.as_str();

    // Compute JWK thumbprint (RFC 7638) — canonical JSON with sorted keys
    let thumbprint = {
        let jwk = signing_key.jwk();
        // Use serde_json to produce sorted, compact JSON
        let canonical = canonical_jwk_json(jwk)?;
        b64(&Sha256::digest(canonical.as_bytes()))
    };

    // Determine directory URL from --server/--directory-url/--ca
    let dir_url = resolve_directory_url(cli)?;

    // Get ACME directory
    info!("Getting directory...");
    let (dir_json, status, _) =
        do_request(&client, &dir_url, None, "Error getting directory").await?;
    if !status.is_success() {
        bail!("Error getting directory: HTTP {status}\n{dir_json}");
    }
    let directory: Directory =
        serde_json::from_value(dir_json).context("Failed to parse directory response")?;

    // When --renew-before or --ari is active, the gate applies regardless of --force default
    let force_active = if cli.min_days_left.is_none() && !cli.ari {
        cli.force
    } else {
        false
    };

    // --- Days-based expiry gate ---
    #[allow(clippy::unnecessary_unwrap)]
    if let Some(days) = cli.min_days_left {
        let cert_path = cli.existing_cert.as_ref().unwrap();
        let (_, cert) = x509_parser::pem::parse_x509_pem(&std::fs::read(cert_path)?)
            .map_err(|e| anyhow!("Invalid PEM: {e}"))?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&cert.contents)
            .context("Failed to parse certificate")?;
        // Extract notAfter as epoch seconds (approximate — good enough for days gate)
        let not_after = parsed.tbs_certificate.validity.not_after;
        let expiry_secs = not_after.timestamp();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let remaining_days = (expiry_secs - now_secs) / 86400;
        if remaining_days > days as i64 && !force_active {
            info!(
                "Certificate valid for {remaining_days} days (> {days} days). Skipping issuance."
            );
            return Ok(String::new());
        }
    }

    // --- ARI pre-check (RFC 9773) ---
    #[allow(clippy::unnecessary_unwrap)]
    let cert_id_for_replaces = if cli.ari && cli.existing_cert.is_some() {
        let cert_path = cli.existing_cert.as_ref().unwrap();
        let aki_serial = crate::commands::ari::cert_id_from_file(cert_path)?;
        let renewal_url = directory.renewal_info.as_deref().unwrap_or("/renewalInfo"); // fallback, unlikely for ARI-enabled CAs
        let url = if renewal_url.starts_with("http") {
            format!("{renewal_url}/{aki_serial}")
        } else {
            let dir_url = reqwest::Url::parse(&dir_url).context("Invalid directory URL")?;
            format!(
                "{}://{}{}/{}/{}",
                dir_url.scheme(),
                dir_url.host_str().unwrap_or(""),
                if let Some(port) = dir_url.port() {
                    format!(":{port}")
                } else {
                    String::new()
                },
                renewal_url.trim_matches('/'),
                aki_serial
            )
        };
        let resp = client
            .get(&url)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .context("Failed to query ARI endpoint")?;
        if resp.status() == 200 {
            let ari_info: serde_json::Value = resp.json().await?;
            let start = ari_info["suggestedWindow"]["start"].as_str();
            let end = ari_info["suggestedWindow"]["end"].as_str();
            // Simple check: if server returned 200 with a window, trust it
            if start.is_some() && end.is_some() {
                // Parse RFC3339: "2026-07-15T06:53:25Z"
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let parse_rfc3339 = |ts: &str| -> i64 {
                    ts.trim_end_matches('Z')
                        .replace('T', " ")
                        .split(' ')
                        .next()
                        .map(|d| {
                            let p: Vec<&str> = d.split('-').collect();
                            if p.len() == 3 {
                                let y: i64 = p[0].parse().unwrap_or(1970);
                                let m: u32 = p[1].parse().unwrap_or(1);
                                let d: u32 = p[2].parse().unwrap_or(1);
                                ((y - 1970) * 365 + m as i64 * 30 + d as i64) * 86400
                            } else {
                                0
                            }
                        })
                        .unwrap_or(0)
                };
                let w_start = start.map(parse_rfc3339).unwrap_or(0);
                let w_end = end.map(parse_rfc3339).unwrap_or(0);
                if now_secs < w_start || now_secs > w_end {
                    info!("ARI: not in renewal window. Skipping issuance.");
                    return Ok(String::new());
                }
                info!("ARI: in renewal window. Proceeding.");
            }
        } else if resp.status() == 404 {
            info!("ARI: no suggestion from server. Proceeding.");
        }
        Some(aki_serial)
    } else if cli.ari {
        info!("ARI: --ari set but no --existing-cert, skipping ARI check");
        None
    } else if cli.existing_cert.is_some() {
        // --existing-cert without --ari: compute certID for replaces field
        let cert_path = cli.existing_cert.as_ref().unwrap();
        let aki_serial = crate::commands::ari::cert_id_from_file(cert_path)?;
        Some(aki_serial)
    } else {
        None
    };
    info!("Directory found!");
    debug!(
        "Directory endpoints: newNonce={} newAccount={} newOrder={}",
        directory.new_nonce,
        directory.new_account,
        directory.new_order
    );

    // Register account
    info!("Registering account...");
    let mut acct_location: Option<String> = None;

    // External Account Binding (RFC 8555 §7.3.4)
    let eab = if let (Some(ref kid), Some(ref hmac_key)) = (&cli.eab_kid, &cli.eab_hmac_key) {
        let jwk_json = serde_json::to_string(signing_key.jwk())?;
        let eab_protected = serde_json::json!({
            "alg": cli.eab_hmac_alg,
            "kid": kid,
            "url": directory.new_account,
        });
        let protected64 = b64(serde_json::to_string(&eab_protected)?.as_bytes());
        let payload64 = b64(jwk_json.as_bytes());
        let signing_input = format!("{protected64}.{payload64}");

        let decoded_key = URL_SAFE_NO_PAD
            .decode(hmac_key.as_bytes())
            .context("EAB HMAC key is not valid base64url")?;
        use hmac::{Hmac, Mac};
        let sig: Vec<u8> = match cli.eab_hmac_alg.as_str() {
            "HS256" => {
                let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&decoded_key)
                    .context("EAB HMAC key invalid")?;
                mac.update(signing_input.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            "HS384" => {
                let mut mac = Hmac::<sha2::Sha384>::new_from_slice(&decoded_key)
                    .context("EAB HMAC key invalid")?;
                mac.update(signing_input.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            "HS512" => {
                let mut mac = Hmac::<sha2::Sha512>::new_from_slice(&decoded_key)
                    .context("EAB HMAC key invalid")?;
                mac.update(signing_input.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            other => bail!("Unsupported EAB HMAC algorithm: {other} (use HS256, HS384, or HS512)"),
        };

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
            "termsOfServiceAgreed": cli.agree_tos,
            "contact": contact,
        })
    } else {
        serde_json::json!({
            "termsOfServiceAgreed": cli.agree_tos,
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
    #[allow(clippy::unnecessary_unwrap)]
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
                info!("Updated contact details:\n{}", contact_lines.join("\n"));
            }
        }
    }

    // Create new order
    info!("Creating new order...");
    let identifiers: Vec<serde_json::Value> = domains
        .iter()
        .map(|d| {
            let id_type = if d.parse::<std::net::IpAddr>().is_ok() {
                "ip"
            } else {
                "dns"
            };
            serde_json::json!({"type": id_type, "value": d})
        })
        .collect();
    let mut order_payload = serde_json::json!({"identifiers": identifiers});
    if let Some(ref p) = cli.profile {
        order_payload["profile"] = serde_json::json!(p);
    }
    if let Some(ref cert_id) = cert_id_for_replaces {
        order_payload["replaces"] = serde_json::json!(cert_id);
    }

    let (mut order, _, mut headers) = send_signed_request(
        &client,
        &directory.new_order,
        Some(&order_payload),
        "Error creating new order",
        signing_key,
        &acct_location,
        &directory,
    )
    .await?;

    // If the CA says the certificate has already been replaced, retry
    // without the "replaces" field (same approach as acme.sh / lego).
    if order.get("type").and_then(|t| t.as_str())
        == Some("urn:ietf:params:acme:error:alreadyReplaced")
    {
        info!("Certificate already replaced, retrying without 'replaces'.");
        order_payload
            .as_object_mut()
            .and_then(|o| o.remove("replaces"));
        let (new_order, _, new_headers) = send_signed_request(
            &client,
            &directory.new_order,
            Some(&order_payload),
            "Error creating new order (retry without replaces)",
            signing_key,
            &acct_location,
            &directory,
        )
        .await?;
        order = new_order;
        headers = new_headers;
        info!("Order created (without replaces)!");
    }

    let order_location = headers
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Missing order Location header"))?;
    let finalize_url = order["finalize"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing finalize URL in order"))?;

    info!("Order created!");

    // Process authorizations
    let authorizations: Vec<String> = order["authorizations"]
        .as_array()
        .ok_or_else(|| anyhow!("No authorizations in order"))?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    debug!(
        "Order details: order_url={} finalize_url={} authorizations={}",
        order_location, finalize_url, authorizations.len()
    );

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
        let auth_status = authorization["status"].as_str().unwrap_or("");
        debug!(
            "Authorization: url={} domain={} status={}",
            auth_url, domain, auth_status
        );
        if auth_status == "valid" {
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
            .ok_or_else(|| anyhow!("Missing challenge token for {domain}"))?;
        debug!(
            "Selected challenge: url={} type={} token={}",
            challenge["url"].as_str().unwrap_or(""),
            challenge["type"].as_str().unwrap_or(""),
            token
        );
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

        // Pre-compute DNS challenge info if needed (available for cleanup after poll)
        let dns_cleanup_info: Option<(String, String)> = if challenge_type == "dns-01"
            || challenge_type == "dns-persist-01"
            || challenge_type == "dns-account-01"
        {
            let txt_value = if challenge_type == "dns-account-01" {
                // dns-account-01 (draft): TXT = SHA256(thumbprint), no token
                crate::b64(&sha2::Sha256::digest(thumbprint.as_bytes()))
            } else {
                dns::dns_txt_value(&cleaned_token, &thumbprint)
            };
            let effective_domain = if let Some(ref alias) = cli.challenge_alias {
                if alias.starts_with('=') {
                    // =alias.com → TXT at alias.com (no _acme-challenge. prefix)
                    alias.trim_start_matches('=').to_string()
                } else {
                    // alias.com → TXT at _acme-challenge.alias.com
                    format!("_acme-challenge.{alias}")
                }
            } else {
                dns::cname::resolve_challenge_domain(&domain)
                    .await
                    .trim_end_matches('.')
                    .to_string()
            };
            if effective_domain != domain {
                debug!(
                    "DNS challenge delegated from {} -> {}",
                    domain,
                    effective_domain
                );
            }
            dns::create_provider(&cli.dns_provider)?.present(&effective_domain, &txt_value)?;
            if challenge_type == "dns-01" {
                Some((effective_domain, txt_value))
            } else {
                // dns-persist-01 / dns-account-01: intentionally skip cleanup
                None
            }
        } else {
            None
        };

        // Standalone server handle — RAII guard aborts the listener on every
        // exit path (loop iteration end, bail, panic unwind).
        let mut server_guard = StandaloneServerGuard(None);

        if challenge_type == "tls-alpn-01" {
            let port = cli.tls_alpn01_port.unwrap_or(443);
            server_guard.0 =
                Some(challenge::tls_alpn::start(&domain, &keyauthorization, port).await?);
            info!("TLS-ALPN-01 server started on port {port} for {domain}");
        } else if challenge_type == "http-01" {
            if cli.standalone {
                let port = cli.http01_port.unwrap_or(80);
                server_guard.0 =
                    Some(challenge::http::start(port, &cleaned_token, &keyauthorization).await?);
                info!("Standalone HTTP server started on port {port} for {domain}");
            } else {
                let wellknown_path =
                    Path::new(cli.acme_dir.as_deref().unwrap_or(".")).join(&cleaned_token);
                fs::write(&wellknown_path, &keyauthorization).with_context(|| {
                    format!("Failed to write challenge file: {:?}", wellknown_path)
                })?;

                if !cli.disable_check {
                    let check_port_str =
                        cli.check_port.map(|p| format!(":{p}")).unwrap_or_default();
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
            }
        } else if challenge_type == "dns-01" || challenge_type == "dns-persist-01" {
            // DNS challenge already handled above
        } else {
            bail!("Unsupported challenge type: {challenge_type}");
        }

        // Submit challenge + poll (wrapped so cleanup runs on failure too)
        let poll_result = async {
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
            poll_until_not(
                &client,
                auth_url,
                &["pending", "processing"],
                &format!("Error checking challenge status for {domain}"),
                signing_key,
                &acct_location,
                &directory,
            )
            .await
        }
        .await;

        // Clean up challenge (file or DNS) — always runs, success or failure
        if challenge_type == "http-01" {
            let wellknown_path =
                Path::new(cli.acme_dir.as_deref().unwrap_or(".")).join(&cleaned_token);
            let _ = fs::remove_file(&wellknown_path);
        }
        // http-standalone / tls-alpn-01: cleanup is automatic — server_guard drops here
        if let Some((eff_domain, txt_val)) = dns_cleanup_info {
            let _ = dns::create_provider(&cli.dns_provider)
                .and_then(|p| p.cleanup(&eff_domain, &txt_val));
        }
        // dns-persist-01 / dns-account-01: intentionally skip cleanup — record persists

        // Check poll result
        let authorization = poll_result?;
        if authorization["status"].as_str() != Some("valid") {
            bail!("Challenge did not pass for {domain}: {authorization}");
        }
        info!("{domain} verified!");
    }

    // Finalize the order with CSR
    info!("Signing certificate...");
    let csr_der = get_csr_der(
        cli.csr
            .as_deref()
            .ok_or_else(|| anyhow!("--csr is required"))?,
    )?;
    let finalize_payload = serde_json::json!({
        "csr": b64(&csr_der),
    });

    debug!(
        "Finalizing order: order_url={} finalize_url={}",
        order_location, finalize_url
    );
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

    let certificate_pem =
        download_certificate(&client, cert_url, signing_key, &acct_location, &directory).await?;

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

    let body = resp
        .text()
        .await
        .context("Failed to read certificate response")?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize request/response log (requires --output)
    init_log(cli.log.as_deref(), cli.log_level)?;

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

    // --list-ca flag
    if cli.list_ca {
        ca::print_ca_table(false);
        return Ok(());
    }

    // Extract fields needed before cli.command is consumed
    let acct_key = cli.account_key.clone();
    let acct_cb = cli.ca_bundle.clone();
    let acct_ins = cli.insecure;
    let _acct_dir = resolve_directory_url(&cli)?;

    // Dispatch subcommand
    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Account {
                action,
                verbose,
                server,
                directory_url,
                ..
            } => {
                let key = acct_key
                    .as_deref()
                    .ok_or_else(|| anyhow!("--account-key is required for account commands"))?;
                let sk = parse_account_key(key)?;
                let dir = directory_url.unwrap_or_else(|| {
                    ca::resolve(&server)
                        .ok()
                        .map(|r| r.directory_url())
                        .unwrap_or_default()
                });
                if verbose >= 1 {
                    eprintln!("[account] Server: {dir}");
                }
                return match action {
                    AccountAction::Show => {
                        commands::account::show(&sk, &dir, acct_cb.as_deref(), acct_ins, verbose)
                            .await
                    }
                    AccountAction::Update { email } => {
                        commands::account::update(
                            &sk,
                            &dir,
                            email.as_deref(),
                            acct_cb.as_deref(),
                            acct_ins,
                            verbose,
                        )
                        .await
                    }
                    AccountAction::Register {
                        email,
                        agree_tos,
                        eab_kid,
                        eab_hmac_key,
                        eab_hmac_alg,
                    } => {
                        commands::account::register(
                            &sk,
                            &dir,
                            email.as_deref(),
                            agree_tos,
                            eab_kid.as_deref(),
                            eab_hmac_key.as_deref(),
                            &eab_hmac_alg,
                            acct_cb.as_deref(),
                            acct_ins,
                            verbose,
                        )
                        .await
                    }
                    AccountAction::Unregister => {
                        commands::account::unregister(
                            &sk,
                            &dir,
                            acct_cb.as_deref(),
                            acct_ins,
                            verbose,
                        )
                        .await
                    }
                    AccountAction::ChangeKey { new_key } => {
                        commands::account::change_key(
                            &sk,
                            &dir,
                            &new_key,
                            acct_cb.as_deref(),
                            acct_ins,
                            verbose,
                        )
                        .await
                    }
                };
            }
            Commands::Completions { shell } => {
                use clap::CommandFactory;
                use clap_complete::{generate, Shell};
                let sh = match shell.as_str() {
                    "bash" => Shell::Bash,
                    "zsh" => Shell::Zsh,
                    "fish" => Shell::Fish,
                    "powershell" => Shell::PowerShell,
                    _ => bail!("Unsupported shell: {shell}. Use bash, zsh, fish, or powershell."),
                };
                let mut cmd = Cli::command();
                generate(sh, &mut cmd, "acme-tiny-rs", &mut std::io::stdout());
                return Ok(());
            }
            Commands::Thumbprint { account_key } => return commands::thumbprint::run(&account_key),
            Commands::Version => return commands::version::run(),
            Commands::Ari {
                cert,
                directory_url,
                server,
                insecure,
                verbose,
            } => {
                let dir_url = directory_url.unwrap_or_else(|| {
                    ca::resolve(&server)
                        .ok()
                        .map(|r| r.directory_url())
                        .unwrap_or_else(|| {
                            ca::KNOWN_CAS
                                .iter()
                                .find(|c| c.id == "letsencrypt")
                                .unwrap()
                                .directory_url
                                .to_string()
                        })
                });
                return commands::ari::run(&cert, &dir_url, insecure, verbose).await;
            }
            Commands::ListCa { json, no_header } => {
                if json {
                    let list = ca::cas_as_json();
                    println!("{}", serde_json::to_string_pretty(&list)?);
                } else {
                    ca::print_ca_table(no_header);
                }
                return Ok(());
            }
            Commands::InspectCa {
                server,
                verbose,
                insecure,
            } => {
                return ca::inspect_ca(&server, verbose, insecure).await;
            }
            Commands::Inspect {
                domains,
                port,
                json,
                insecure,
                lint,
                no_header,
            } => {
                return commands::inspect::run(&domains, port, json, insecure, lint, no_header)
                    .await;
            }
            Commands::Dump {
                domain,
                port,
                output,
                format,
                insecure,
            } => {
                return commands::dump::run(&domain, port, output.as_deref(), format, insecure)
                    .await;
            }
            Commands::Revoke {
                cert,
                account_key,
                directory_url,
                server,
                reason,
                ca_bundle,
                insecure,
            } => {
                let dir_url = directory_url.unwrap_or_else(|| {
                    ca::resolve(&server)
                        .ok()
                        .map(|r| r.directory_url())
                        .unwrap_or_else(|| {
                            ca::KNOWN_CAS
                                .iter()
                                .find(|c| c.id == "letsencrypt")
                                .unwrap()
                                .directory_url
                                .to_string()
                        })
                });
                return commands::revoke::run(
                    &cert,
                    &account_key,
                    &dir_url,
                    reason,
                    ca_bundle.as_deref(),
                    insecure,
                )
                .await;
            }
        }
    }

    // Parse account key — supports RSA (PKCS#1/PKCS#8), ECDSA P-256/P-384 (SEC1/PKCS#8)
    let signing_key = parse_account_key(
        cli.account_key
            .as_deref()
            .ok_or_else(|| anyhow!("--account-key is required"))?,
    )?;

    // Parse CSR (replaces: openssl req -in csr -noout -text)
    let domains = parse_csr(
        cli.csr
            .as_deref()
            .ok_or_else(|| anyhow!("--csr is required"))?,
    )?;

    // Wildcard domains require dns-01 challenge (RFC 8555 §8.4)
    let has_wildcard = domains.iter().any(|d| d.starts_with("*."));
    let challenge_type = cli.challenge_type.to_lowercase();
    let is_dns_challenge = challenge_type == "dns-01"
        || challenge_type == "dns-persist-01"
        || challenge_type == "dns-account-01";
    if has_wildcard && !is_dns_challenge {
        bail!(
            "Wildcard domain requires --challenge-type dns-01.\n\
             Wildcard domains found: {}\n\
             Add: --challenge-type dns-01 [--dns-provider <provider>]",
            domains
                .iter()
                .filter(|d| d.starts_with("*."))
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // IP addresses cannot use DNS challenge (RFC 8738)
    let has_ip = domains
        .iter()
        .any(|d| d.parse::<std::net::IpAddr>().is_ok());
    if has_ip && is_dns_challenge {
        bail!(
            "IP addresses require http-01 or tls-alpn-01 challenge.\n\
             IP addresses found: {}\n\
             Use: --challenge-type http-01",
            domains
                .iter()
                .filter(|d| d.parse::<std::net::IpAddr>().is_ok())
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Run ACME flow (post-hook runs regardless of success or failure)
    // --pre-hook
    #[allow(unused_must_use)]
    if let Some(ref cmd) = cli.pre_hook {
        hook::Hook::Pre(cmd.clone()).run(&[]);
    }
    let result = get_crt(&cli, &signing_key, &domains).await;
    if let Some(ref cmd) = cli.post_hook {
        #[allow(unused_must_use)]
        let _ = hook::Hook::Post(cmd.clone()).run(&[]);
    }
    let certificate = result?;

    // ARI skip: empty certificate means no issuance needed
    if certificate.is_empty() {
        if let Some(ref cmd) = cli.notify_hook {
            let _ = hook::Hook::Notify(cmd.clone()).run(&[]);
        }
        return Ok(());
    }

    if let Some(ref path) = cli.output {
        // Atomic write: write to temp file first, then rename
        let tmp = format!("{path}.tmp-{}", std::process::id());
        std::fs::write(&tmp, &certificate)
            .with_context(|| format!("Failed to write certificate to {tmp}"))?;
        std::fs::rename(&tmp, path).with_context(|| format!("Failed to rename {tmp} to {path}"))?;
        info!("Certificate written to {path}");
    } else {
        print!("{certificate}");
    }

    // Run hooks after certificate is written to disk
    let cert_path = cli.output.as_deref().unwrap_or("");
    let key_path = cli.account_key.as_deref().unwrap_or("");
    let primary_domain = domains.first().map(|s| s.as_str()).unwrap_or("");
    let envs = hook::Hook::acme_env_vars(cert_path, key_path, primary_domain);
    #[allow(unused_must_use)]
    {
        if let Some(ref cmd) = cli.renew_hook {
            hook::Hook::Renew(cmd.clone()).run(&envs);
        }
        if let Some(ref cmd) = cli.deploy_hook {
            hook::Hook::Deploy(cmd.clone()).run(&envs);
        }
        if let Some(ref cmd) = cli.notify_hook {
            hook::Hook::Notify(cmd.clone()).run(&envs);
        }
    }

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
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
            ])
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
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
            ])
            .arg(&key_path)
            .output()
            .unwrap();
        let sk = parse_account_key(key_path.to_str().unwrap()).unwrap();
        let sig = sk.sign(b"test signing data").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_parse_account_key_ed25519() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ed25519.key");
        std::process::Command::new("openssl")
            .args(["genpkey", "-algorithm", "Ed25519", "-out"])
            .arg(&key_path)
            .output()
            .unwrap();
        let result = parse_account_key(key_path.to_str().unwrap());
        assert!(result.is_ok(), "{:?}", result.err());
        let sk = result.unwrap();
        assert_eq!(sk.alg(), "EdDSA");
        let sig = sk.sign(b"test").unwrap();
        assert!(!sig.is_empty());
    }
}
