/// Linode DNS providers — v4 (current, Bearer token) and v3 (deprecated, API key).
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi
use anyhow::{anyhow, bail, Result};
use std::env;
use crate::dns::DnsProvider;

// ── v4 (current) ──
const LINODE_V4_API: &str = "https://api.linode.com/v4/domains";

pub struct LinodeV4Dns { token: String, client: reqwest::blocking::Client }

impl LinodeV4Dns {
    pub fn new() -> Result<Self> {
        Ok(Self { token: env::var("LINODE_V4_API_KEY")?, client: reqwest::blocking::Client::new() })
    }
    fn headers(&self) -> String { format!("Bearer {}", self.token) }
    fn get_domain_id(&self, domain: &str) -> Result<(u64, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let resp: serde_json::Value = self.client.get(format!("{LINODE_V4_API}/{root}"))
                .header("Authorization", self.headers()).send()?.json()?;
            if let Some(id) = resp["id"].as_u64() { return Ok((id, sub)); }
        }
        bail!("Linode v4 domain not found");
    }
}

impl DnsProvider for LinodeV4Dns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (domain_id, sub) = self.get_domain_id(domain)?;
        let body = serde_json::json!({"type":"TXT","name":sub,"target":value,"ttl_sec":300});
        self.client.post(format!("{LINODE_V4_API}/{domain_id}/records"))
            .header("Authorization", self.headers()).header("Content-Type","application/json")
            .json(&body).send()?;
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let (domain_id, sub) = self.get_domain_id(domain)?;
        let resp: serde_json::Value = self.client.get(format!("{LINODE_V4_API}/{domain_id}/records"))
            .header("Authorization", self.headers()).send()?.json()?;
        if let Some(records) = resp["data"].as_array() {
            for r in records {
                if r["name"].as_str() == Some(&sub) && r["type"].as_str() == Some("TXT") {
                    if let Some(id) = r["id"].as_u64() {
                        let _ = self.client.delete(format!("{LINODE_V4_API}/{domain_id}/records/{id}"))
                            .header("Authorization", self.headers()).send();
                    }
                }
            }
        }
        Ok(())
    }
}

// ── v3 (deprecated) ──
const LINODE_V3_API: &str = "https://api.linode.com/";

pub struct LinodeV3Dns { api_key: String, client: reqwest::blocking::Client }

impl LinodeV3Dns {
    pub fn new() -> Result<Self> {
        Ok(Self { api_key: env::var("LINODE_API_KEY").map_err(|_| anyhow!("LINODE_API_KEY required (v3 deprecated, prefer v4)"))?, client: reqwest::blocking::Client::new() })
    }
    fn url(&self, action: &str, params: &str) -> String {
        format!("{LINODE_V3_API}?api_key={}&api_action={action}{params}", self.api_key)
    }
    fn get_domain_id(&self, domain: &str) -> Result<(u64, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let resp: serde_json::Value = self.client.get(self.url("domain.list", "")).send()?.json()?;
            if let Some(data) = resp["DATA"].as_array() {
                if data.iter().any(|d| d["DOMAIN"].as_str() == Some(&root)) {
                    if let Some(d) = data.iter().find(|d| d["DOMAIN"].as_str() == Some(&root)) {
                        return Ok((d["DOMAINID"].as_u64().unwrap_or(0), sub));
                    }
                }
            }
        }
        bail!("Linode v3 domain not found for {domain}");
    }
}

impl DnsProvider for LinodeV3Dns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (domain_id, sub) = self.get_domain_id(domain)?;
        let params = format!("&DomainID={domain_id}&Type=TXT&Name={sub}&Target={value}");
        let _ = self.client.get(self.url("domain.resource.create", &params)).send()?;
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let (domain_id, sub) = self.get_domain_id(domain)?;
        let params = format!("&DomainID={domain_id}");
        let resp: serde_json::Value = self.client.get(self.url("domain.resource.list", &params)).send()?.json()?;
        if let Some(data) = resp["DATA"].as_array() {
            for r in data {
                if r["NAME"].as_str() == Some(&sub) && r["TYPE"].as_str() == Some("TXT") {
                    if let Some(rid) = r["RESOURCEID"].as_u64() {
                        let dp = format!("&DomainID={domain_id}&ResourceID={rid}");
                        let _ = self.client.get(self.url("domain.resource.delete", &dp)).send();
                    }
                }
            }
        }
        Ok(())
    }
}
