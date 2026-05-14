//! `dump` subcommand — TLS certificate chain dump.
//!
//! Equivalent to `openssl s_client -showcerts -connect <host>:<port> -servername <host>`.
//! Outputs certificates in PEM (default), DER, or text format.

use std::io::{self, Write};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustls::pki_types::{DnsName, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Output format for certificate dump.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum DumpFormat {
    /// PEM-encoded certificate chain (default, matches openssl s_client -showcerts)
    Pem,
    /// DER-encoded leaf certificate (binary)
    Der,
    /// Human-readable certificate details
    Text,
}

/// Dump the TLS certificate chain from a domain.
pub async fn run(domain: &str, default_port: u16, output: Option<&str>, format: DumpFormat, insecure: bool) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = if insecure {
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>], _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> { Ok(ServerCertVerified::assertion()) }
            fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
            fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { vec![rustls::SignatureScheme::RSA_PKCS1_SHA256, rustls::SignatureScheme::ECDSA_NISTP256_SHA256] }
        }
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(config));

    // Parse host[:port]
    let (host, port) = if let Some((h, p)) = domain.rsplit_once(':') {
        (h, p.parse::<u16>().unwrap_or(default_port))
    } else {
        (domain, default_port)
    };

    let addr = format!("{host}:{port}");

    // TCP connect
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connection failed: {addr}"))?;

    // TLS handshake
    let dns_name = DnsName::try_from(host.to_string())
        .with_context(|| format!("Invalid hostname: {host}"))?;
    let server_name = ServerName::DnsName(dns_name);
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake failed for {host}"))?;

    // Extract peer certificates
    let (_tcp, conn) = tls_stream.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("No certificate presented by {host}"))?;

    if certs.is_empty() {
        bail!("Empty certificate chain from {host}");
    }

    // Format and output
    let mut writer: Box<dyn Write> = match output {
        Some(path) => {
            let file = std::fs::File::create(path)
                .with_context(|| format!("Failed to create output file: {path}"))?;
            Box::new(io::BufWriter::new(file))
        }
        None => Box::new(io::stdout().lock()),
    };

    match format {
        DumpFormat::Pem => {
            for cert in certs {
                pem_encode(cert.as_ref(), &mut writer)?;
            }
        }
        DumpFormat::Der => {
            // Leaf certificate only
            writer
                .write_all(certs[0].as_ref())
                .context("Failed to write DER output")?;
        }
        DumpFormat::Text => {
            for (i, cert) in certs.iter().enumerate() {
                if i > 0 {
                    writeln!(writer)?;
                }
                text_dump(cert.as_ref(), i, &mut writer)?;
            }
        }
    }

    Ok(())
}

/// Encode DER bytes as PEM with 64-char line wrapping.
fn pem_encode(der: &[u8], w: &mut dyn Write) -> Result<()> {
    let b64 = STANDARD.encode(der);
    writeln!(w, "-----BEGIN CERTIFICATE-----")?;
    for chunk in b64.as_bytes().chunks(64) {
        writeln!(w, "{}", std::str::from_utf8(chunk).unwrap())?;
    }
    // Ensure trailing newline if last line wasn't exactly 64 chars
    if b64.len() % 64 != 0 || b64.is_empty() {
        // writeln already added a newline, this is fine
    }
    writeln!(w, "-----END CERTIFICATE-----")?;
    Ok(())
}

/// Human-readable certificate dump (similar to `openssl x509 -text`).
fn text_dump(der: &[u8], index: usize, w: &mut dyn Write) -> Result<()> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .context("Failed to parse certificate")?;

    writeln!(w, "Certificate {index}")?;
    writeln!(w, "  Subject: {}", cert.subject())?;

    // Issuer
    writeln!(w, "  Issuer: {}", cert.issuer())?;

    // Validity
    let not_before = cert.validity().not_before;
    let not_after = cert.validity().not_after;
    writeln!(
        w,
        "  Validity: {}",
        not_before
            .to_rfc2822()
            .unwrap_or_else(|_| "?".to_string())
    )?;
    writeln!(
        w,
        "            {}",
        not_after
            .to_rfc2822()
            .unwrap_or_else(|_| "?".to_string())
    )?;

    // Serial
    let serial = cert.raw_serial();
    write!(w, "  Serial: ")?;
    for byte in serial {
        write!(w, "{byte:02x}")?;
    }
    writeln!(w)?;

    // Signature algorithm
    writeln!(w, "  Signature Algorithm: {}", cert.signature_algorithm.algorithm)?;

    // Subject Public Key Info
    let spki = cert.public_key();
    writeln!(w, "  Public Key Algorithm: {}", spki.algorithm.algorithm)?;

    // Extensions
    let exts = cert.extensions();
    if !exts.is_empty() {
        writeln!(w, "  Extensions ({}):", exts.len())?;
        for ext in exts {
            writeln!(w, "    {}: {:?}", ext.oid, ext.parsed_extension())?;
        }
    }

    // Fingerprints
    use sha1::Digest;
    let sha1_fp = sha1::Sha1::digest(der);
    let sha256_fp = sha2::Sha256::digest(der);
    write!(w, "  SHA-1 Fingerprint: ")?;
    for byte in sha1_fp.iter() {
        write!(w, "{byte:02x}")?;
    }
    writeln!(w)?;
    write!(w, "  SHA-256 Fingerprint: ")?;
    for byte in sha256_fp.iter() {
        write!(w, "{byte:02x}")?;
    }
    writeln!(w)?;

    Ok(())
}
