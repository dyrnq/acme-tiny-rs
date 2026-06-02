/// Gandi LiveDNS provider.
/// Requires GANDI_LIVEDNS_KEY env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_gandi_livedns.sh
use anyhow::{bail, Result};
use std::env;
use crate::dns::DnsProvider;
pub struct GandiDns { key: String, client: reqwest::blocking::Client }
impl GandiDns {
    pub fn new() -> Result<Self> { Ok(Self { key: env::var("GANDI_LIVEDNS_KEY")?, client: reqwest::blocking::Client::new() }) }
}
impl DnsProvider for GandiDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let body = serde_json::json!({"rrset_type":"TXT","rrset_values":[value],"rrset_ttl":300});
        let resp = self.client.put(format!("https://api.gandi.net/v5/livedns/domains/{domain}/records/_acme-challenge/TXT"))
            .header("Authorization", format!("Apikey {}", self.key))
            .header("Content-Type","application/json").json(&body).send()?;
        if !resp.status().is_success() { bail!("Gandi error"); }
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let _ = self.client.delete(format!("https://api.gandi.net/v5/livedns/domains/{domain}/records/_acme-challenge/TXT"))
            .header("Authorization", format!("Apikey {}", self.key)).send();
        Ok(())
    }
}
