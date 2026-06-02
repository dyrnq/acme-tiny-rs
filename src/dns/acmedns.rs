/// acme-dns DNS provider (self-hosted ACME DNS server with REST API).
/// Auto-registers if no credentials; requires CNAME delegation to acme-dns server.
/// Requires ACMEDNS_BASE_URL (default: https://auth.acme-dns.io).
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_acmedns.sh
use anyhow::{bail, Result};
use std::env;
use crate::dns::DnsProvider;

pub struct AcmeDnsDns {
    base_url: String,
    username: String,
    password: String,
    subdomain: String,
    client: reqwest::blocking::Client,
}

impl AcmeDnsDns {
    pub fn new() -> Result<Self> {
        let mut s = Self {
            base_url: env::var("ACMEDNS_BASE_URL").unwrap_or_else(|_| "https://auth.acme-dns.io".into()),
            username: env::var("ACMEDNS_USERNAME").unwrap_or_default(),
            password: env::var("ACMEDNS_PASSWORD").unwrap_or_default(),
            subdomain: env::var("ACMEDNS_SUBDOMAIN").unwrap_or_default(),
            client: reqwest::blocking::Client::new(),
        };
        // Auto-register if no credentials
        if s.username.is_empty() || s.password.is_empty() {
            let resp: serde_json::Value = s.client
                .post(format!("{}/register", s.base_url))
                .send()?.json()?;
            s.username = resp["username"].as_str().unwrap_or("").into();
            s.password = resp["password"].as_str().unwrap_or("").into();
            s.subdomain = resp["subdomain"].as_str().unwrap_or("").into();
            let fulldomain = resp["fulldomain"].as_str().unwrap_or("");
            println!(
                "[acme-dns] Auto-registered. Create this CNAME record:\n  _acme-challenge.{{domain}} -> {fulldomain}"
            );
        }
        Ok(s)
    }
}

impl DnsProvider for AcmeDnsDns {
    fn present(&self, _domain: &str, value: &str) -> Result<()> {
        let body = serde_json::json!({"subdomain": self.subdomain, "txt": value});
        let resp: serde_json::Value = self.client
            .post(format!("{}/update", self.base_url))
            .header("X-Api-User", &self.username)
            .header("X-Api-Key", &self.password)
            .json(&body).send()?.json()?;
        if resp.get("txt").and_then(|v| v.as_str()) != Some(value) {
            bail!("acme-dns update failed");
        }
        Ok(())
    }
    fn cleanup(&self, _domain: &str, _value: &str) -> Result<()> { Ok(()) }
}
