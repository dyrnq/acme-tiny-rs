/// BunnyCDN DNS provider.
/// Requires BUNNY_API_KEY env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_bunny.sh
use anyhow::{anyhow, bail, Result};
use std::env;
use crate::dns::DnsProvider;
pub struct BunnyDns { key: String, client: reqwest::blocking::Client }
impl BunnyDns {
    pub fn new() -> Result<Self> { Ok(Self { key: env::var("BUNNY_API_KEY")?, client: reqwest::blocking::Client::new() }) }
}
impl DnsProvider for BunnyDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let body = serde_json::json!({"type":0,"value":value,"name":"_acme-challenge","ttl":60});
        let resp = self.client.put(format!("https://api.bunny.net/dnszone/{domain}/records"))
            .header("AccessKey", &self.key).header("Content-Type","application/json").json(&body).send()?;
        if resp.status().as_u16() >= 400 { bail!("Bunny error"); }
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let r: serde_json::Value = self.client.get(format!("https://api.bunny.net/dnszone/{domain}"))
            .header("AccessKey", &self.key).send()?.json()?;
        if let Some(records) = r["Records"].as_array() {
            for rec in records {
                if rec["Name"].as_str() == Some("_acme-challenge") && rec["Type"].as_u64() == Some(0) {
                    if let Some(id) = rec["Id"].as_u64() {
                        let _ = self.client.delete(format!("https://api.bunny.net/dnszone/{domain}/records/{id}"))
                            .header("AccessKey", &self.key).send();
                    }
                }
            }
        }
        Ok(())
    }
}

