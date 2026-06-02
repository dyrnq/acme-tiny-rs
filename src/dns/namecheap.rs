/// Namecheap DNS provider.
/// Requires NAMECHEAP_API_KEY and NAMECHEAP_USERNAME env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_namecheap.sh
use anyhow::{bail, Result};
use std::env;
use crate::dns::DnsProvider;
pub struct NamecheapDns { key: String, user: String, client: reqwest::blocking::Client }
impl NamecheapDns {
    pub fn new() -> Result<Self> { Ok(Self {
        key: env::var("NAMECHEAP_API_KEY")?,
        user: env::var("NAMECHEAP_USERNAME")?,
        client: reqwest::blocking::Client::new(),
    })}
    fn get_domain_parts(&self, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let tld = parts[i..].join(".");
            let sld = if i > 0 { parts[i-1] } else { "" };
            let url = format!("https://api.namecheap.com/xml.response?ApiUser={}&ApiKey={}&UserName={}&Command=namecheap.domains.dns.getHosts&ClientIp=127.0.0.1&SLD={sld}&TLD={tld}",
                self.user, self.key, self.user);
            let resp = self.client.get(&url).send()?.text()?;
            if resp.contains("Domain") && !resp.contains("Error") { return Ok((root, sub)); }
        }
        bail!("Namecheap domain not found");
    }
}
impl DnsProvider for NamecheapDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub) = self.get_domain_parts(domain)?;
        let parts: Vec<&str> = root.split('.').collect();
        let sld = parts[0];
        let tld = parts[1..].join(".");
        let url = format!("https://api.namecheap.com/xml.response?ApiUser={}&ApiKey={}&UserName={}&Command=namecheap.domains.dns.setHosts&ClientIp=127.0.0.1&SLD={sld}&TLD={tld}&HostName1={sub}&RecordType1=TXT&Address1={value}&TTL1=60",
            self.user, self.key, self.user);
        let _ = self.client.post(&url).send()?;
        Ok(())
    }
    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let (root, _sub) = self.get_domain_parts(domain)?;
        let parts: Vec<&str> = root.split('.').collect();
        let sld = parts[0];
        let tld = parts[1..].join(".");
        let url = format!("https://api.namecheap.com/xml.response?ApiUser={}&ApiKey={}&UserName={}&Command=namecheap.domains.dns.setHosts&ClientIp=127.0.0.1&SLD={sld}&TLD={tld}",
            self.user, self.key, self.user);
        let _ = self.client.post(&url).send()?;
        Ok(())
    }
}
