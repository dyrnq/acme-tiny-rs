/// Cloudflare DNS API provider.
///
/// Requires CF_API_TOKEN or CF_API_KEY + CF_API_EMAIL environment variables.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_cf.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

pub struct CloudflareDns {
    token: String,
    client: reqwest::blocking::Client,
}

impl CloudflareDns {
    pub fn new() -> Result<Self> {
        let token = env::var("CF_API_TOKEN")
            .or_else(|_| {
                let key = env::var("CF_API_KEY")?;
                let email = env::var("CF_API_EMAIL")?;
                Ok(format!("{email}:{key}"))
            })
            .map_err(|_: env::VarError| {
                anyhow::anyhow!(
                    "Cloudflare DNS requires CF_API_TOKEN or (CF_API_KEY + CF_API_EMAIL) env vars"
                )
            })?;

        Ok(Self {
            token,
            client: reqwest::blocking::Client::new(),
        })
    }

    fn get_zone_id(&self, domain: &str) -> Result<String> {
        // Extract root domain (last two parts for most domains)
        let parts: Vec<&str> = domain.split('.').collect();
        let root = if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            domain.to_string()
        };

        let resp: serde_json::Value = self
            .client
            .get("https://api.cloudflare.com/client/v4/zones")
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .query(&[("name", &root)])
            .send()?
            .json()?;

        let zones = resp["result"]
            .as_array()
            .ok_or_else(|| anyhow!("Cloudflare API error: {resp}"))?;
        let zone = zones
            .first()
            .ok_or_else(|| anyhow!("Zone not found for domain: {root}"))?;
        zone["id"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing zone id"))
    }

    fn get_record_id(&self, zone_id: &str, name: &str) -> Result<Option<String>> {
        let resp: serde_json::Value = self
            .client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .query(&[("type", "TXT"), ("name", name)])
            .send()?
            .json()?;

        let records = resp["result"]
            .as_array()
            .ok_or_else(|| anyhow!("Cloudflare API error: {resp}"))?;
        Ok(records
            .first()
            .and_then(|r| r["id"].as_str().map(|s| s.to_string())))
    }
}

impl DnsProvider for CloudflareDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{domain}");
        let zone_id = self.get_zone_id(domain)?;

        // Remove existing record if present
        if let Some(id) = self.get_record_id(&zone_id, &record_name)? {
            let _ = self
                .client
                .delete(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{id}"
                ))
                .header("Authorization", format!("Bearer {}", self.token))
                .header("Content-Type", "application/json")
                .send()?;
        }

        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        });

        let resp: serde_json::Value = self
            .client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?
            .json()?;

        if !resp["success"].as_bool().unwrap_or(false) {
            bail!("Cloudflare API error: {resp}");
        }

        println!("[cloudflare] TXT record set: {record_name} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{domain}");
        let zone_id = self.get_zone_id(domain)?;

        if let Some(id) = self.get_record_id(&zone_id, &record_name)? {
            let _ = self
                .client
                .delete(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{id}"
                ))
                .header("Authorization", format!("Bearer {}", self.token))
                .header("Content-Type", "application/json")
                .send()?;
            println!("[cloudflare] TXT record removed: {record_name}");
        }
        Ok(())
    }
}
