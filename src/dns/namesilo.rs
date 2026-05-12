/// NameSilo DNS provider.
/// Requires NAMESILO_API_KEY env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_namesilo.sh
use anyhow::{anyhow, bail, Result};
use std::env;
use crate::dns::DnsProvider;
pub struct NameSiloDns { key: String, client: reqwest::blocking::Client }
impl NameSiloDns {
    pub fn new() -> Result<Self> { Ok(Self { key: env::var("NAMESILO_API_KEY")?, client: reqwest::blocking::Client::new() }) }
    fn get_record_id(&self, domain: &str, sub: &str) -> Result<Option<String>> {
        let resp: serde_json::Value = self.client.get(format!(
            "https://www.namesilo.com/api/dnsListRecords?version=1&type=xml&key={}&domain={domain}", self.key))
            .send()?.json()?;
        Ok(resp["reply"]["resource_record"].as_array().and_then(|a| a.iter()
            .find(|r| r["host"].as_str() == Some(sub) && r["type"].as_str() == Some("TXT"))
            .and_then(|r| r["record_id"].as_str().map(|s| s.to_string()))))
    }
}
impl DnsProvider for NameSiloDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let url = format!("https://www.namesilo.com/api/dnsAddRecord?version=1&type=xml&key={}&domain={domain}&rrhost=_acme-challenge&rrvalue={value}&rrtype=TXT&rrttl=3607", self.key);
        self.client.get(&url).send()?;
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        if let Ok(Some(id)) = self.get_record_id(domain, "_acme-challenge") {
            let url = format!("https://www.namesilo.com/api/dnsDeleteRecord?version=1&type=xml&key={}&domain={domain}&rrid={id}", self.key);
            let _ = self.client.get(&url).send();
        }
        Ok(())
    }
}
