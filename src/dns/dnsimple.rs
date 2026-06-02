/// DNSimple DNS provider.
///
/// Requires DNSimple_OAUTH_TOKEN env var.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_dnsimple.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

const DNSIMPLE_API: &str = "https://api.dnsimple.com/v2";

pub struct DnsimpleDns {
    oauth_token: String,
    client: reqwest::blocking::Client,
}

impl DnsimpleDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            oauth_token: env::var("DNSimple_OAUTH_TOKEN")
                .map_err(|_| anyhow!("DNSimple_OAUTH_TOKEN env var required"))?,
            client: reqwest::blocking::Client::new(),
        })
    }

    fn get_account_id(&self) -> Result<String> {
        let resp: serde_json::Value = self
            .client
            .get(format!("{DNSIMPLE_API}/whoami"))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", self.oauth_token))
            .send()?
            .json()?;

        if resp["data"]["account"].is_null()
            || resp["data"]["account"]
                .as_object()
                .is_none_or(|o| o.is_empty())
        {
            bail!("No account associated with this DNSimple token");
        }

        resp["data"]["account"]["id"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Failed to get account ID from DNSimple"))
    }

    fn find_zone(&self, account_id: &str, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        let _prev_i = 1;

        for i in 2..=parts.len() {
            let zone = parts[i.saturating_sub(1)..].join(".");
            let sub = parts[..i.saturating_sub(1)].join(".");

            let resp: serde_json::Value = self
                .client
                .get(format!("{DNSIMPLE_API}/{account_id}/zones/{}", zone))
                .header("Accept", "application/json")
                .header("Authorization", format!("Bearer {}", self.oauth_token))
                .send()?
                .json()?;

            // If no "not found" in the response, this is a valid zone
            if !resp["message"].as_str().unwrap_or("").contains("not found")
                && resp["errors"].as_array().is_none_or(|e| e.is_empty())
            {
                return Ok((zone, sub));
            }
        }

        bail!("No matching zone found for {} in DNSimple", domain);
    }
}

impl DnsProvider for DnsimpleDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{}", domain);
        let account_id = self.get_account_id()?;
        let (zone, sub) = self.find_zone(&account_id, &record_name)?;

        let body = serde_json::json!({
            "type": "TXT",
            "name": sub,
            "content": value,
            "ttl": 120
        });

        let resp: serde_json::Value = self
            .client
            .post(format!("{DNSIMPLE_API}/{account_id}/zones/{zone}/records"))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", self.oauth_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?
            .json()?;

        if resp["errors"].as_array().is_some_and(|e| !e.is_empty()) {
            bail!("DNSimple API error: {resp}");
        }

        println!("[dnsimple] TXT record set: {record_name} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{}", domain);
        let account_id = match self.get_account_id() {
            Ok(id) => id,
            Err(_) => return Ok(()),
        };
        let (zone, sub) = match self.find_zone(&account_id, &record_name) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        // List all records and find matching ones
        let resp: serde_json::Value = self
            .client
            .get(format!(
                "{DNSIMPLE_API}/{account_id}/zones/{zone}/records?per_page=5000&name={sub}&type=TXT"
            ))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", self.oauth_token))
            .send()?
            .json()?;

        if let Some(records) = resp["data"].as_array() {
            for record in records {
                if record["name"].as_str() == Some(&sub) && record["type"].as_str() == Some("TXT") {
                    if let Some(rid) = record["id"].as_u64() {
                        let _ = self
                            .client
                            .delete(format!(
                                "{DNSIMPLE_API}/{account_id}/zones/{zone}/records/{rid}"
                            ))
                            .header("Accept", "application/json")
                            .header("Authorization", format!("Bearer {}", self.oauth_token))
                            .send()?;
                    }
                }
            }
            println!("[dnsimple] TXT record removed: {record_name}");
        }
        Ok(())
    }
}
