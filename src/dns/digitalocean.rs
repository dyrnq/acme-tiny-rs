/// DigitalOcean DNS provider.
///
/// Requires DO_API_KEY env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_dgon.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

const DO_API: &str = "https://api.digitalocean.com/v2/domains";

pub struct DigitalOceanDns {
    api_key: String,
    client: reqwest::blocking::Client,
}

impl DigitalOceanDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            api_key: env::var("DO_API_KEY")
                .map_err(|_| anyhow!("DO_API_KEY env var required"))?,
            client: reqwest::blocking::Client::new(),
        })
    }

    fn find_zone_and_sub(&self, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");

            let resp: serde_json::Value = self
                .client
                .get(&format!("{DO_API}/{root}"))
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .send()?
                .json()?;

            if resp["domain"]["name"].as_str() == Some(&root) {
                return Ok((root, sub));
            }
        }

        // If exact zone lookup fails, try listing all zones and matching
        let mut page: Option<String> = None;
        loop {
            let url = match &page {
                Some(next) => next.clone(),
                None => format!("{DO_API}?per_page=200"),
            };

            let resp: serde_json::Value = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .send()?
                .json()?;

            if let Some(domains) = resp["domains"].as_array() {
                for d in domains {
                    if let Some(zone_name) = d["name"].as_str() {
                        if domain.ends_with(zone_name) {
                            let sub = domain
                                .strip_suffix(&format!(".{}", zone_name))
                                .unwrap_or(domain)
                                .to_string();
                            return Ok((zone_name.to_string(), sub));
                        }
                    }
                }
            }

            // Check for next page
            if let Some(links) = resp["links"]["pages"].as_object() {
                if let Some(next) = links.get("next") {
                    if let Some(next_url) = next.as_str() {
                        page = Some(next_url.to_string());
                        continue;
                    }
                }
            }
            break;
        }

        bail!("No matching zone found for {}", domain);
    }
}

impl DnsProvider for DigitalOceanDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{}", domain);
        let (zone, sub) = self.find_zone_and_sub(&record_name)?;

        let body = serde_json::json!({
            "type": "TXT",
            "name": sub,
            "data": value,
            "ttl": 120
        });

        let resp: serde_json::Value = self
            .client
            .post(format!("{DO_API}/{zone}/records"))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?
            .json()?;

        if resp["id"].is_null() && resp["domain_record"].is_null() {
            bail!("DigitalOcean API error: {resp}");
        }

        println!("[digitalocean] TXT record set: {record_name} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{}", domain);
        let (zone, sub) = match self.find_zone_and_sub(&record_name) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        // List records and find matching ones to delete
        let resp: serde_json::Value = self
            .client
            .get(format!("{DO_API}/{zone}/records?type=TXT&name={sub}&per_page=200"))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .send()?
            .json()?;

        if let Some(records) = resp["domain_records"].as_array() {
            for record in records {
                if record["name"].as_str() == Some(&sub) && record["type"].as_str() == Some("TXT") {
                    if let Some(rid) = record["id"].as_u64() {
                        let _ = self
                            .client
                            .delete(format!("{DO_API}/{zone}/records/{rid}"))
                            .header("Authorization", format!("Bearer {}", self.api_key))
                            .header("Content-Type", "application/json")
                            .send()?;
                    }
                }
            }
            println!("[digitalocean] TXT record removed: {record_name}");
        }
        Ok(())
    }
}
