/// deSEC DNS provider.
/// Requires DESEC_TOKEN env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_desec.sh
use anyhow::{bail, Result};
use std::env;
use crate::dns::DnsProvider;
pub struct DesecDns { token: String, client: reqwest::blocking::Client }
impl DesecDns {
    pub fn new() -> Result<Self> { Ok(Self { token: env::var("DESEC_TOKEN")?, client: reqwest::blocking::Client::new() }) }
}
impl DnsProvider for DesecDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let body = serde_json::json!([{"type":"TXT","records":[format!("\"{value}\"")],"ttl":60}]);
        let resp = self.client.post(format!("https://desec.io/api/v1/domains/{domain}/rrsets/"))
            .header("Authorization", format!("Token {}", self.token))
            .header("Content-Type","application/json").json(&body).send()?;
        if !resp.status().is_success() { bail!("deSEC error: {}", resp.text()?); }
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let sub = "_acme-challenge";
        let resp = self.client.get(format!("https://desec.io/api/v1/domains/{domain}/rrsets/{sub}/TXT/"))
            .header("Authorization", format!("Token {}", self.token)).send()?;
        if resp.status().is_success() {
            let _ = self.client.delete(format!("https://desec.io/api/v1/domains/{domain}/rrsets/{sub}/TXT/"))
                .header("Authorization", format!("Token {}", self.token)).send();
        }
        Ok(())
    }
}
