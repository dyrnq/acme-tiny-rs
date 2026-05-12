/// Netlify DNS provider.
/// Requires NETLIFY_ACCESS_TOKEN env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_netlify.sh
use anyhow::{bail, Result};
use std::env;
use crate::dns::DnsProvider;

pub struct NetlifyDns { token: String, client: reqwest::blocking::Client }

impl NetlifyDns {
    pub fn new() -> Result<Self> {
        Ok(Self { token: env::var("NETLIFY_ACCESS_TOKEN")?, client: reqwest::blocking::Client::new() })
    }
    fn get_zone_id(&self, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let resp = self.client
                .get(format!("https://api.netlify.com/api/v1/dns_zones/{root}"))
                .header("Authorization", format!("Bearer {}", self.token)).send()?;
            if resp.status().is_success() {
                let body: serde_json::Value = resp.json()?;
                if let Some(id) = body["id"].as_str() { return Ok((id.to_string(), sub)); }
            }
        }
        bail!("Netlify zone not found for {domain}");
    }
    fn get_record_id(&self, zone_id: &str, hostname: &str) -> Result<Option<String>> {
        let resp = self.client
            .get(format!("https://api.netlify.com/api/v1/dns_zones/{zone_id}/dns_records"))
            .header("Authorization", format!("Bearer {}", self.token)).send()?;
        let records: Vec<serde_json::Value> = resp.json()?;
        Ok(records.iter().find(|r| r["hostname"].as_str() == Some(hostname) && r["type"].as_str() == Some("TXT"))
            .and_then(|r| r["id"].as_str().map(|s| s.to_string())))
    }
}

impl DnsProvider for NetlifyDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (zone_id, sub) = self.get_zone_id(domain)?;
        let hostname = format!("_acme-challenge.{sub}");
        let body = serde_json::json!({"type":"TXT","hostname":hostname,"value":value,"ttl":10});
        let resp = self.client
            .post(format!("https://api.netlify.com/api/v1/dns_zones/{zone_id}/dns_records"))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type","application/json").json(&body).send()?;
        if !resp.status().is_success() { bail!("Netlify error: {}", resp.text().unwrap_or_default()); }
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let (zone_id, sub) = self.get_zone_id(domain)?;
        let hostname = format!("_acme-challenge.{sub}");
        if let Ok(Some(id)) = self.get_record_id(&zone_id, &hostname) {
            let _ = self.client
                .delete(format!("https://api.netlify.com/api/v1/dns_zones/{zone_id}/dns_records/{id}"))
                .header("Authorization", format!("Bearer {}", self.token)).send();
        }
        Ok(())
    }
}
