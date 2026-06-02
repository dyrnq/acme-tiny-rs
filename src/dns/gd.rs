/// GoDaddy DNS API provider.
///
/// Requires GD_Key and GD_Secret env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_gd.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

const GD_API: &str = "https://api.godaddy.com/v1";

pub struct GoDaddyDns {
    key: String,
    secret: String,
    client: reqwest::blocking::Client,
}

impl GoDaddyDns {
    pub fn new() -> Result<Self> {
        let key = env::var("GD_Key").map_err(|_| anyhow!("GD_Key env var required"))?;
        let secret = env::var("GD_Secret").map_err(|_| anyhow!("GD_Secret env var required"))?;
        Ok(Self {
            key,
            secret,
            client: reqwest::blocking::Client::new(),
        })
    }

    fn auth_headers(&self) -> String {
        format!("sso-key {}:{}", self.key, self.secret)
    }

    fn get_root_domain(&self, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let url = format!("{GD_API}/domains/{root}");
            let resp = self
                .client
                .get(&url)
                .header("Authorization", self.auth_headers())
                .send()?;
            if resp.status().is_success() {
                return Ok((root, sub));
            }
        }
        bail!("Domain not found in GoDaddy: {domain}");
    }

    fn get_existing_records(&self, domain: &str, subdomain: &str) -> Result<Vec<String>> {
        let url = format!("{GD_API}/domains/{domain}/records/TXT/{subdomain}");
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_headers())
            .send()?;
        if resp.status().as_u16() == 404 {
            return Ok(vec![]);
        }
        if !resp.status().is_success() {
            bail!("GoDaddy API error");
        }
        let records: Vec<serde_json::Value> = resp.json()?;
        Ok(records
            .iter()
            .filter_map(|r| r["data"].as_str().map(|s| s.to_string()))
            .collect())
    }
}

impl DnsProvider for GoDaddyDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub) = self.get_root_domain(domain)?;
        let fqdn = format!("{sub}.{root}");
        // Preserve existing records, merge with new one (like acme-sh)
        let mut values = self.get_existing_records(&root, &fqdn).unwrap_or_default();
        if values.contains(&value.to_string()) {
            println!("[godaddy] TXT record already exists: _acme-challenge.{domain}");
            return Ok(());
        }
        values.push(value.to_string());
        let body: Vec<serde_json::Value> = values
            .iter()
            .map(|v| serde_json::json!({"data": v}))
            .collect();
        let url = format!("{GD_API}/domains/{root}/records/TXT/{fqdn}");
        let resp = self
            .client
            .put(&url)
            .header("Authorization", self.auth_headers())
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            bail!("GoDaddy API error: {}", resp.text().unwrap_or_default());
        }
        println!("[godaddy] TXT record set: _acme-challenge.{domain} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub) = self.get_root_domain(domain)?;
        let fqdn = format!("{sub}.{root}");
        let values: Vec<String> = self
            .get_existing_records(&root, &fqdn)
            .unwrap_or_default()
            .into_iter()
            .filter(|v| v != value)
            .collect();
        let url = format!("{GD_API}/domains/{root}/records/TXT/{fqdn}");
        if values.is_empty() {
            let _ = self
                .client
                .delete(&url)
                .header("Authorization", self.auth_headers())
                .send();
        } else {
            let body: Vec<serde_json::Value> = values
                .iter()
                .map(|v| serde_json::json!({"data": v}))
                .collect();
            let _ = self
                .client
                .put(&url)
                .header("Authorization", self.auth_headers())
                .header("Content-Type", "application/json")
                .json(&body)
                .send();
        }
        println!("[godaddy] TXT record removed: _acme-challenge.{domain}");
        Ok(())
    }
}
