/// CNAME auto-follow for DNS-01 / DNS-persist-01 challenge delegation.
///
/// When a user creates a CNAME record like:
///   `_acme-challenge.example.com CNAME _acme-challenge.delegated.net.`
/// the DNS challenge FQDN should resolve through the CNAME chain to find the
/// actual target where the TXT record will be written.
///
/// This is modeled after lego's `lookupCNAME` — zero configuration, automatic
/// discovery, default-on, and harmless when no CNAME exists.

use std::net::UdpSocket;

/// Maximum CNAME chain length (matches lego's limit).
const MAX_CNAME_HOPS: usize = 50;

/// Encode a domain name for a DNS query (3www6example3com0 format).
fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Decode a DNS name from response bytes starting at offset, return (name, next_offset).
fn decode_dns_name(data: &[u8], start: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut end = 0;

    loop {
        if pos >= data.len() { break; }
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped { end = pos + 1; }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 2 > data.len() { break; }
            let ptr = ((len & 0x3F) as usize) << 8 | data[pos + 1] as usize;
            if !jumped { end = pos + 2; }
            pos = ptr;
            jumped = true;
            continue;
        }
        // Normal label
        pos += 1;
        if pos + len > data.len() { break; }
        labels.push(String::from_utf8_lossy(&data[pos..pos + len]).to_lowercase());
        pos += len;
    }

    (labels.join("."), if jumped { end } else { end.max(pos + 1) })
}

/// Build a DNS query for CNAME record.
fn build_cname_query(fqdn: &str) -> Vec<u8> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u16) & 0xFFFF;
    let name = encode_dns_name(fqdn);
    let mut query = vec![
        (id >> 8) as u8, id as u8,  // ID
        0x01, 0x00,                  // Standard query
        0x00, 0x01,                  // QDCOUNT = 1
        0x00, 0x00,                  // ANCOUNT = 0
        0x00, 0x00,                  // NSCOUNT = 0
        0x00, 0x00,                  // ARCOUNT = 0
    ];
    query.extend(&name);
    query.extend(&[0x00, 0x05]); // CNAME
    query.extend(&[0x00, 0x01]); // IN class
    query
}

/// Parse CNAME from DNS response, returns Option<target_fqdn>.
fn parse_cname_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 { return None; }
    let qdcount = ((data[4] as u16) << 8) | data[5] as u16;
    let ancount = ((data[6] as u16) << 8) | data[7] as u16;

    // Skip header (12 bytes) + question section
    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = decode_dns_name(data, pos);
        pos = next + 4; // skip QTYPE + QCLASS
    }

    // Parse answer section
    for _ in 0..ancount {
        let (_, next) = decode_dns_name(data, pos);
        pos = next;
        if pos + 10 > data.len() { break; }
        let rtype = ((data[pos] as u16) << 8) | data[pos + 1] as u16;
        let rdlen = ((data[pos + 8] as u16) << 8) | data[pos + 9] as u16;
        pos += 10;
        if rtype == 5 && rdlen > 0 {
            // CNAME record
            let (cname, _) = decode_dns_name(data, pos);
            return Some(cname);
        }
        pos += rdlen as usize;
    }
    None
}

/// Lookup CNAME for a single FQDN using system DNS (sync, blocking).
fn lookup_cname_sync(fqdn: &str) -> Option<String> {
    let query = build_cname_query(fqdn);
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;

    // Try common system resolvers
    for dns_ip in &["8.8.8.8:53", "1.1.1.1:53"] {
        if socket.send_to(&query, dns_ip).is_ok() {
            let mut buf = [0u8; 512];
            if let Ok(len) = socket.recv(&mut buf) {
                return parse_cname_response(&buf[..len]);
            }
        }
    }
    None
}

/// Follow CNAME records starting from `fqdn` and return the final target.
async fn follow_cname(fqdn: &str) -> String {
    let fqdn_owned = fqdn.to_string();

    // Run DNS queries in a blocking context
    let result = tokio::task::spawn_blocking(move || {
        let mut current = fqdn_owned;
        for _ in 0..MAX_CNAME_HOPS {
            match lookup_cname_sync(&current) {
                Some(target) if target != current => {
                    log::info!("CNAME delegation: {} -> {}", current, target);
                    current = target;
                }
                _ => break,
            }
        }
        current
    });

    match result.await {
        Ok(s) => s,
        Err(_) => fqdn.to_string(),
    }
}

/// Resolve the base domain that the ACME DNS challenge should use.
pub async fn resolve_challenge_domain(domain: &str) -> String {
    let challenge_fqdn = format!("_acme-challenge.{}", domain);
    let target = follow_cname(&challenge_fqdn).await;

    if target != challenge_fqdn {
        target
            .strip_prefix("_acme-challenge.")
            .and_then(|s| s.strip_suffix('.').or(Some(s)))
            .unwrap_or(&target)
            .to_string()
    } else {
        domain.to_string()
    }
}
