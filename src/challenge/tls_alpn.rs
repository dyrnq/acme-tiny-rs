//! TLS-ALPN-01 challenge (built-in TLS server on port 443).
//! Generates a self-signed cert with acmeValidation extension (OID 1.3.6.1.5.5.7.1.31)
//! and negotiates ALPN protocol "acme-tls/1".

use anyhow::{Context, Result};
use log::info;
use rcgen::{CertificateParams, KeyPair, CustomExtension};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use sha2::Digest;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub async fn start(domain: &str, key_auth: &str) -> Result<tokio::task::JoinHandle<()>> {
    let domain = domain.to_string();
    let alpn_protocol = b"acme-tls/1".to_vec();

    let digest = sha2::Sha256::digest(key_auth.as_bytes());

    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![domain.clone()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.custom_extensions.push(CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 5, 5, 7, 1, 31],
        digest.to_vec(),
    ));

    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;
    config.alpn_protocols = vec![alpn_protocol];

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("0.0.0.0:443").await
        .with_context(|| "Failed to bind port 443 for TLS-ALPN-01 server")?;

    info!("TLS-ALPN-01 server listening on port 443 for {domain}");

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let _ = acceptor.accept(stream).await;
                    });
                }
                Err(_) => break,
            }
        }
    }))
}
