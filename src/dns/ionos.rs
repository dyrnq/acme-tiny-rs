/// IONOS DNS provider.
/// Requires IONOS_PREFIX and IONOS_SECRET env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_ionos_cloud.sh
use anyhow::{anyhow, bail, Result};
use std::env;
use crate::dns::DnsProvider;

pub struct IonosDns { key: String, client: reqwest::blocking::Client }
impl IonosDns {
    pub fn new() -> Result<Self> { Ok(Self {
        key: format!("{}.{}", env::var("IONOS_PREFIX")?, env::var("IONOS_SECRET")?),
        client: reqwest::blocking::Client::new(),
    })}
    fn get_zone(&self, domain: &str) -> Result<(String, String)> {
        let r: serde_json::Value = self.client.get("https://api.hosting.ionos.com/dns/v1/zones")
            .header("X-API-Key", &self.key).send()?.json()?;
        let zones = r.as_array().ok_or_else(|| anyhow!("IONOS: no zones"))?;
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            if let Some(z) = zones.iter().find(|z| z["name"].as_str() == Some(&root)) {
                return Ok((z["id"].as_str().unwrap_or("").to_string(), root));
            }
        }
        bail!("IONOS zone not found");
    }
}
impl DnsProvider for IonosDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (zid, _zone) = self.get_zone(domain)?;
        let r: serde_json::Value = self.client.get(format!("https://api.hosting.ionos.com/dns/v1/zones/{zid}"))
            .header("X-API-Key", &self.key).send()?.json()?;
        let mut records: Vec<serde_json::Value> = r["records"].as_array().cloned().unwrap_or_default();
        records.push(serde_json::json!({"name":"_acme-challenge","type":"TXT","content":value,"ttl":60,"prio":0,"disabled":false}));
        self.client.put(format!("https://api.hosting.ionos.com/dns/v1/zones/{zid}"))
            .header("X-API-Key", &self.key).header("Content-Type","application/json").json(&records).send()?;
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let (zid, _zone) = self.get_zone(domain)?;
        let r: serde_json::Value = self.client.get(format!("https://api.hosting.ionos.com/dns/v1/zones/{zid}"))
            .header("X-API-Key", &self.key).send()?.json()?;
        let records: Vec<serde_json::Value> = r["records"].as_array().map_or(vec![], |a| a.iter()
            .filter(|r| r["name"].as_str() != Some("_acme-challenge") || r["type"].as_str() != Some("TXT"))
            .cloned().collect());
        let _ = self.client.put(format!("https://api.hosting.ionos.com/dns/v1/zones/{zid}"))
            .header("X-API-Key", &self.key).header("Content-Type","application/json").json(&records).send();
        Ok(())
    }
}
