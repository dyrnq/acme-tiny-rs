use crate::dns::DnsProvider;
/// Porkbun DNS provider.
/// Requires PORKBUN_API_KEY and PORKBUN_SECRET_API_KEY env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_porkbun.sh
use anyhow::{bail, Result};
use std::env;
pub struct PorkbunDns {
    key: String,
    secret: String,
    client: reqwest::blocking::Client,
}
impl PorkbunDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            key: env::var("PORKBUN_API_KEY")?,
            secret: env::var("PORKBUN_SECRET_API_KEY")?,
            client: reqwest::blocking::Client::new(),
        })
    }
    fn api(&self, endpoint: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let resp: serde_json::Value = self
            .client
            .post(format!("https://api.porkbun.com/api/json/v3/{endpoint}"))
            .json(body)
            .send()?
            .json()?;
        if resp["status"] != "SUCCESS" {
            bail!("Porkbun error: {resp}");
        }
        Ok(resp)
    }
    fn get_record_id(&self, domain: &str) -> Result<Option<String>> {
        let body = serde_json::json!({"apikey":self.key,"secretapikey":self.secret});
        let resp = self.api(&format!("dns/retrieve/{domain}"), &body)?;
        Ok(resp["records"].as_array().and_then(|a| {
            a.iter()
                .find(|r| {
                    r["name"].as_str() == Some("_acme-challenge")
                        && r["type"].as_str() == Some("TXT")
                })
                .and_then(|r| r["id"].as_str().map(|s| s.to_string()))
        }))
    }
}
impl DnsProvider for PorkbunDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let body = serde_json::json!({"apikey":self.key,"secretapikey":self.secret,"name":"_acme-challenge","type":"TXT","content":value,"ttl":600});
        self.api(&format!("dns/create/{domain}"), &body)?;
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        if let Ok(Some(id)) = self.get_record_id(domain) {
            let body = serde_json::json!({"apikey":self.key,"secretapikey":self.secret});
            let _ = self.api(&format!("dns/delete/{domain}/{id}"), &body);
        }
        Ok(())
    }
}
