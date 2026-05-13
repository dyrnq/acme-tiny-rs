//! HTTP-01 standalone server (--standalone mode).
//! Listens on a TCP port and serves ACME challenge responses directly,
//! without writing files to disk.

use anyhow::{Context, Result};
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn start(port: u16, token: &str, key_auth: &str) -> Result<tokio::task::JoinHandle<()>> {
    let token = token.to_string();
    let key_auth = key_auth.to_string();
    let expected_path = format!("GET /.well-known/acme-challenge/{token} HTTP");
    let response_ok = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{key_auth}",
        key_auth.len()
    );
    let response_404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await
        .with_context(|| format!("Failed to bind port {port} for standalone server"))?;

    info!("Standalone HTTP server listening on port {port}");

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 512];
                    if let Ok(Ok(n)) = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        stream.read(&mut buf),
                    ).await {
                        let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                        let resp = if req.starts_with(&expected_path) {
                            response_ok.as_bytes()
                        } else {
                            response_404.as_bytes()
                        };
                        let _ = stream.write_all(resp).await;
                    }
                }
                Err(_) => break,
            }
        }
    }))
}
