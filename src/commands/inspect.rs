//! `inspect` subcommand — TLS certificate information display.
//!
//! Connects to each domain via TLS, retrieves the leaf certificate, and
//! prints a table of key fields (default) or JSON output (with `--json`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rustls::pki_types::{DnsName, ServerName};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Serialize)]
struct CertInfo {
    domain: String,
    port: u16,
    subject_cn: String,
    issuer_o: String,
    not_before: String,
    not_after: String,
    days_left: i64,
    serial: String,
    #[serde(rename = "sig_alg")]
    signature_algorithm: String,
    #[serde(rename = "key_alg")]
    public_key_algorithm: String,
    self_signed: bool,
    warnings: Vec<String>,
}

/// Check TLS certificates for one or more domains.
pub async fn run(
    domains: &[String],
    default_port: u16,
    json: bool,
    insecure: bool,
    lint: bool,
    no_header: bool,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = if insecure {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                ]
            }
        }
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(config));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut results: Vec<CertInfo> = Vec::new();

    for domain_arg in domains {
        let (host, port) = if let Some((h, p)) = domain_arg.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
        } else {
            (domain_arg.clone(), default_port)
        };

        let addr = format!("{host}:{port}");
        let label = format!("{host}:{port}");

        let tcp = match TcpStream::connect(&addr).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{label:<30} connection failed: {e}");
                continue;
            }
        };

        let dns_name = match DnsName::try_from(host.clone()) {
            Ok(n) => n,
            Err(_) => {
                eprintln!("{label:<30} invalid hostname");
                continue;
            }
        };
        let server_name = ServerName::DnsName(dns_name);

        let tls_stream = match connector.connect(server_name, tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{label:<30} TLS handshake failed: {e}");
                continue;
            }
        };

        let (_tcp, conn) = tls_stream.get_ref();
        let certs = match conn.peer_certificates() {
            Some(c) if !c.is_empty() => c,
            _ => {
                eprintln!("{label:<30} no certificate presented");
                continue;
            }
        };

        let cert_der = certs[0].as_ref();
        let (_, cert) = match x509_parser::parse_x509_certificate(cert_der) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{label:<30} failed to parse certificate: {e}");
                continue;
            }
        };

        let subject_cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or("-")
            .to_string();

        let issuer_o = cert
            .issuer()
            .iter_organization()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or("-")
            .to_string();

        let not_before = cert.validity().not_before;
        let not_after = cert.validity().not_after;

        let not_before_str = not_before.to_rfc2822().unwrap_or_else(|_| "-".to_string());
        let not_after_str = not_after.to_rfc2822().unwrap_or_else(|_| "-".to_string());

        let not_after_sec = not_after.timestamp();
        let days_left = (not_after_sec - now) / 86400;

        let serial = cert.raw_serial();
        let serial_str = serial
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");

        let sig_alg = format!("{:?}", cert.signature_algorithm.algorithm);
        let pk = cert.public_key();
        let key_alg = format!("{:?}", pk.algorithm);

        let self_signed = subject_cn == issuer_o && subject_cn != "-";

        let warnings = if lint {
            lint_cert(&cert, now)
        } else {
            Vec::new()
        };

        results.push(CertInfo {
            domain: host,
            port,
            subject_cn,
            issuer_o,
            not_before: not_before_str,
            not_after: not_after_str,
            days_left,
            serial: serial_str,
            signature_algorithm: sig_alg,
            public_key_algorithm: key_alg,
            self_signed,
            warnings,
        });
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        // Table header — skip when --no-header is set
        if !no_header {
            if lint {
                println!(
                    "{:<20} {:>5}  {:<15}  {:<15}  {:>4}  {:>8}  {:^10}  {:^25}  Not After",
                    "Domain", "Port", "Subject CN", "Issuer O", "Days", "SelfSig", "KeyAlg", "Lint"
                );
            } else {
                println!(
                    "{:<20} {:>5}  {:<15}  {:<15}  {:>4}  {:>8}  {:^10}  Not After",
                    "Domain", "Port", "Subject CN", "Issuer O", "Days", "SelfSig", "KeyAlg"
                );
            }
            let sep = "-".repeat(120);
            println!("{sep}");
        }

        for r in &results {
            let self_sig = if r.self_signed { "YES" } else { "no" };
            let lint_col = if r.warnings.is_empty() {
                "OK"
            } else {
                &r.warnings[0]
            };
            if lint {
                println!(
                    "{:<20} {:>5}  {:<15}  {:<15}  {:>4}  {:>8}  {:>10}  {:<25}  {}",
                    r.domain,
                    r.port,
                    truncate(&r.subject_cn, 15),
                    truncate(&r.issuer_o, 15),
                    r.days_left,
                    self_sig,
                    truncate(&r.public_key_algorithm, 10),
                    truncate(lint_col, 25),
                    r.not_after,
                );
            } else {
                println!(
                    "{:<20} {:>5}  {:<15}  {:<15}  {:>4}  {:>8}  {:>10}  {}",
                    r.domain,
                    r.port,
                    truncate(&r.subject_cn, 15),
                    truncate(&r.issuer_o, 15),
                    r.days_left,
                    self_sig,
                    truncate(&r.public_key_algorithm, 10),
                    r.not_after,
                );
            }
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn lint_cert(cert: &x509_parser::certificate::X509Certificate<'_>, now: i64) -> Vec<String> {
    let mut w = Vec::new();
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    if now < not_before {
        w.push("Not yet valid (notBefore is in the future)".into());
    }
    if now > not_after {
        w.push("EXPIRED — notAfter has passed".into());
    }
    if not_after - now < 86400 * 30 {
        w.push("Expires in less than 30 days".into());
    }

    let sig_alg = format!("{:?}", cert.signature_algorithm.algorithm);
    if sig_alg.to_lowercase().contains("sha1") {
        w.push("Weak signature algorithm: SHA-1".into());
    }

    let key_alg = format!("{:?}", cert.public_key().algorithm);
    if key_alg.to_lowercase().contains("rsa") {
        let bits = cert.public_key().raw.len() * 8;
        if bits < 2048 {
            w.push(format!("RSA key too small: {bits} bits (min 2048)"));
        }
    }

    if cert.subject().iter_common_name().next().is_none()
        && cert
            .extensions()
            .iter()
            .all(|e| !format!("{:?}", e.oid).contains("subjectAltName"))
    {
        w.push("No Subject CN or SAN — may be rejected by browsers".into());
    }

    w
}
