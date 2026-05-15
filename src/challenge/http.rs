//! HTTP-01 standalone server (--standalone mode).
//! Listens on a TCP port and serves ACME challenge responses directly,
//! without writing files to disk.

use anyhow::{Context, Result};
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Look up what process is listening on a given TCP port.
#[cfg(target_os = "linux")]
fn find_port_owner(port: u16) -> Option<String> {
    // Parse /proc/net/tcp — find inode for port
    let hex_port = format!("{port:04X}");
    let tcp = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let inode = tcp
        .lines()
        .skip(1)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // local_address is field 1 (0-indexed), format: IP:PORT
            let local = parts.get(2)?;
            let port_hex = local.split(':').nth(1)?;
            if port_hex == hex_port { parts.get(9).map(|s| s.to_string()) } else { None }
        })
        .next()?;

    // Find the process holding this inode
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
        let fd_dir = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        for fd in fd_dir.flatten() {
            let link = std::fs::read_link(fd.path()).ok()?;
            if link.to_str()?.contains(&inode) {
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                    .unwrap_or_default()
                    .replace('\0', " ");
                return Some(format!("{} (pid {}, cmdline: {})", comm.trim(), pid, cmdline.trim()));
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn find_port_owner(_port: u16) -> Option<String> {
    None
}

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
        .with_context(|| {
            if let Some(owner) = find_port_owner(port) {
                format!("Failed to bind port {port} — already in use by {owner}")
            } else {
                format!("Failed to bind port {port} for standalone server")
            }
        })?;

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
