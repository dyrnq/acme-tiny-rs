/// Vultr DNS provider.
/// Requires VULTR_API_KEY env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_vultr.sh
use anyhow::{bail, Result};
use std::env;
use crate::dns::DnsProvider;
pub struct VultrDns { key: String, client: reqwest::blocking::Client }
impl VultrDns {
    pub fn new() -> Result<Self> { Ok(Self { key: env::var("VULTR_API_KEY")?, client: reqwest::blocking::Client::new() }) }
    fn get_domain(&self, domain: &str) -> Result<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let r: serde_json::Value = self.client.get("https://api.vultr.com/v2/domains")
                .header("Authorization", format!("Bearer {}", self.key)).send()?.json()?;
            if r["domains"].as_array().is_some_and(|a| a.iter().any(|d| d["domain"].as_str() == Some(&root))) {
                return Ok(root);
            }
        }
        bail!("Vultr domain not found");
    }
}
impl DnsProvider for VultrDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let root = self.get_domain(domain)?;
        let body = serde_json::json!({"name": "_acme-challenge", "type": "TXT", "data": value, "ttl": 300});
        self.client.post(format!("https://api.vultr.com/v2/domains/{root}/records"))
            .header("Authorization", format!("Bearer {}", self.key)).header("Content-Type","application/json")
            .json(&body).send()?;
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let root = self.get_domain(domain)?;
        let r: serde_json::Value = self.client.get(format!("https://api.vultr.com/v2/domains/{root}/records"))
            .header("Authorization", format!("Bearer {}", self.key)).send()?.json()?;
        if let Some(records) = r["records"].as_array() {
            for rec in records {
                if rec["name"].as_str() == Some("_acme-challenge") && rec["type"].as_str() == Some("TXT") {
                    if let Some(id) = rec["id"].as_str() {
                        let _ = self.client.delete(format!("https://api.vultr.com/v2/domains/{root}/records/{id}"))
                            .header("Authorization", format!("Bearer {}", self.key)).send();
                    }
                }
            }
        }
        Ok(())
    }
}
