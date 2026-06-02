use crate::dns::DnsProvider;
/// DuckDNS provider — simplest DNS API: single GET request.
///
/// Requires DuckDNS_Token env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_duckdns.sh
use anyhow::{bail, Result};
use std::env;

pub struct DuckDnsDns {
    token: String,
    client: reqwest::blocking::Client,
}

impl DuckDnsDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            token: env::var("DuckDNS_Token")?,
            client: reqwest::blocking::Client::new(),
        })
    }
}

impl DnsProvider for DuckDnsDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let u = format!(
            "https://www.duckdns.org/update?domains={domain}&token={}&txt={value}",
            self.token
        );
        let resp = self.client.get(&u).send()?.text()?;
        if !resp.starts_with("OK") {
            bail!("DuckDNS error: {resp}");
        }
        println!("[duckdns] TXT record set: _acme-challenge.{domain} = {value}");
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let u = format!(
            "https://www.duckdns.org/update?domains={domain}&token={}&txt=removed&clear=true",
            self.token
        );
        let _ = self.client.get(&u).send();
        println!("[duckdns] TXT record removed: _acme-challenge.{domain}");
        Ok(())
    }
}
