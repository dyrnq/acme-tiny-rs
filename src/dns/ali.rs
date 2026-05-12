/// Alibaba Cloud (Aliyun) DNS API provider.
///
/// Requires Ali_Key (AccessKey ID) and Ali_Secret (AccessKey Secret) env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_ali.sh
use anyhow::{anyhow, bail, Result};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dns::DnsProvider;

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const ALI_DNS_API: &str = "https://alidns.aliyuncs.com/";

pub struct AlibabaDns {
    key: String,
    secret: String,
    client: reqwest::blocking::Client,
}

impl AlibabaDns {
    pub fn new() -> Result<Self> {
        let key = env::var("Ali_Key").map_err(|_| anyhow!("Ali_Key env var required"))?;
        let secret = env::var("Ali_Secret").map_err(|_| anyhow!("Ali_Secret env var required"))?;
        Ok(Self { key, secret, client: reqwest::blocking::Client::new() })
    }

    fn nonce(&self) -> String {
        format!("{:x}{}", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
            std::process::id())
    }

    fn timestamp(&self) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = now.as_secs();
        let h = (secs % 86400) / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("2026-01-01T{:02}%3A{:02}%3A{:02}Z", h, m, s)
    }

    fn sign(&self, method: &str, query: &str) -> String {
        let to_sign = format!("{}&%2F&{}", method, url_encode_upper(query));
        let key = format!("{}&", self.secret);
        let mut mac = HmacSha1::new_from_slice(key.as_bytes()).expect("HMAC key");
        mac.update(to_sign.as_bytes());
        let result = mac.finalize();
        let b64 = base64::engine::general_purpose::STANDARD.encode(result.into_bytes().as_slice());
        url_encode_upper(&b64)
    }

    fn call_api(&self, params: &[(&str, &str)]) -> Result<serde_json::Value> {
        let mut query = format!(
            "AccessKeyId={}&Format=json&SignatureMethod=HMAC-SHA1&SignatureNonce={}&SignatureVersion=1.0&Timestamp={}&Version=2015-01-09",
            self.key, self.nonce(), self.timestamp()
        );
        for (k, v) in params {
            query.push_str(&format!("&{k}={v}"));
        }
        let sig = self.sign("GET", &query);
        let url = format!("{ALI_DNS_API}?Signature={sig}&{query}");

        let resp: serde_json::Value = self.client.get(&url).send()?.json()?;
        if resp.get("Code").and_then(|c| c.as_str()).is_some() {
            let msg = resp["Message"].as_str().unwrap_or("unknown error");
            bail!("Alibaba DNS API error: {msg}");
        }
        Ok(resp)
    }

    fn get_root_domain(&self, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            if self.call_api(&[("Action", "DescribeDomainRecords"), ("DomainName", &root)]).is_ok() {
                return Ok((root, sub));
            }
        }
        bail!("Cannot find root domain for {domain}");
    }
}

impl DnsProvider for AlibabaDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub) = self.get_root_domain(domain)?;
        self.call_api(&[
            ("Action", "AddDomainRecord"),
            ("DomainName", &root),
            ("RR", &sub),
            ("Type", "TXT"),
            ("Value", value),
        ])?;
        println!("[alibaba] TXT record set: _acme-challenge.{domain} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub) = self.get_root_domain(domain)?;
        if let Ok(resp) = self.call_api(&[
            ("Action", "DescribeDomainRecords"),
            ("DomainName", &root),
            ("RRKeyWord", &sub),
            ("TypeKeyWord", "TXT"),
        ]) {
            if let Some(records) = resp["DomainRecords"]["Record"].as_array() {
                for r in records {
                    if r["RR"].as_str() == Some(&sub) && r["Value"].as_str() == Some(value) {
                        if let Some(id) = r["RecordId"].as_str() {
                            let _ = self.call_api(&[("Action", "DeleteDomainRecord"), ("RecordId", id)]);
                            println!("[alibaba] TXT record removed: _acme-challenge.{domain}");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn url_encode_upper(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => result.push(b as char),
            _ => result.push_str(&format!("%{:02X}", b)),
        }
    }
    result
}

