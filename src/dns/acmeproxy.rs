/// AcmeProxy DNS provider — forwards DNS challenges to a centralized acmeproxy server.
/// Requires ACMEPROXY_ENDPOINT, ACMEPROXY_USERNAME, ACMEPROXY_PASSWORD env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_acmeproxy.sh
use anyhow::{anyhow, bail, Result};
use std::env;
use crate::dns::DnsProvider;

pub struct AcmeProxyDns {
    endpoint: String,
    username: String,
    password: String,
    client: reqwest::blocking::Client,
}

impl AcmeProxyDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            endpoint: env::var("ACMEPROXY_ENDPOINT").map_err(|_| anyhow!("ACMEPROXY_ENDPOINT required"))?,
            username: env::var("ACMEPROXY_USERNAME").unwrap_or_default(),
            password: env::var("ACMEPROXY_PASSWORD").unwrap_or_default(),
            client: reqwest::blocking::Client::new(),
        })
    }

    fn request(&self, domain: &str, value: &str, action: &str) -> Result<()> {
        let body = serde_json::json!({
            "fulldomain": format!("_acme-challenge.{domain}"),
            "txtvalue": value,
            "action": action,
            "username": self.username,
            "password": self.password,
        });
        let resp = self.client.post(&self.endpoint).json(&body).send()?;
        if !resp.status().is_success() { bail!("AcmeProxy error: {}", resp.text().unwrap_or_default()); }
        Ok(())
    }
}

impl DnsProvider for AcmeProxyDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        self.request(domain, value, "present")
    }
    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        self.request(domain, value, "cleanup")
    }
}
