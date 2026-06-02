/// Huawei Cloud DNS provider.
///
/// Requires HUAWEICLOUD_Username, HUAWEICLOUD_Password, HUAWEICLOUD_DomainName.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_huaweicloud.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

const IAM_API: &str = "https://iam.myhuaweicloud.com";
const DNS_API: &str = "https://dns.ap-southeast-1.myhuaweicloud.com";

pub struct HuaweiCloudDns {
    username: String,
    password: String,
    domain_name: String,
    client: reqwest::blocking::Client,
}

impl HuaweiCloudDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            username: env::var("HUAWEICLOUD_Username")
                .map_err(|_| anyhow!("HUAWEICLOUD_Username required"))?,
            password: env::var("HUAWEICLOUD_Password")
                .map_err(|_| anyhow!("HUAWEICLOUD_Password required"))?,
            domain_name: env::var("HUAWEICLOUD_DomainName")
                .map_err(|_| anyhow!("HUAWEICLOUD_DomainName required"))?,
            client: reqwest::blocking::Client::new(),
        })
    }

    fn get_token(&self) -> Result<String> {
        let body = serde_json::json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "password": self.password,
                            "domain": { "name": self.domain_name }
                        }
                    }
                },
                "scope": { "domain": { "name": self.domain_name } }
            }
        });
        let response = self
            .client
            .post(format!("{IAM_API}/v3/auth/tokens"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?;
        let token = response
            .headers()
            .get("X-Subject-Token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("HuaweiCloud: no token in response"))?;
        Ok(token)
    }

    fn get_zone_id(&self, token: &str, domain: &str) -> Result<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let resp: serde_json::Value = self
                .client
                .get(format!("{DNS_API}/v2/zones?name={root}"))
                .header("X-Auth-Token", token)
                .send()?
                .json()?;
            if let Some(zones) = resp["zones"].as_array() {
                if let Some(zone) = zones.first() {
                    return zone["id"]
                        .as_str()
                        .map(|s| s.to_string())
                        .ok_or_else(|| anyhow!("Zone ID not found"));
                }
            }
        }
        bail!("DNS zone not found for {domain}");
    }

    fn get_recordset_id(&self, token: &str, zone_id: &str, name: &str) -> Result<Option<String>> {
        let resp: serde_json::Value = self
            .client
            .get(format!(
                "{DNS_API}/v2/zones/{zone_id}/recordsets?name={name}&type=TXT"
            ))
            .header("X-Auth-Token", token)
            .send()?
            .json()?;
        Ok(resp["recordsets"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| r["id"].as_str().map(|s| s.to_string())))
    }
}

impl DnsProvider for HuaweiCloudDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let token = self.get_token()?;
        let zone_id = self.get_zone_id(&token, domain)?;
        let record_name = format!("_acme-challenge.{domain}.");

        // Delete existing recordset if present
        if let Some(id) = self.get_recordset_id(&token, &zone_id, &record_name)? {
            let _ = self
                .client
                .delete(format!("{DNS_API}/v2/zones/{zone_id}/recordsets/{id}"))
                .header("X-Auth-Token", &token)
                .send();
        }

        let body = serde_json::json!({
            "name": record_name,
            "type": "TXT",
            "records": [format!("\"{value}\"")],
            "ttl": 60,
        });
        let resp = self
            .client
            .post(format!("{DNS_API}/v2/zones/{zone_id}/recordsets"))
            .header("X-Auth-Token", &token)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            bail!("HuaweiCloud DNS error: {}", resp.text().unwrap_or_default());
        }
        println!("[huawei] TXT record set: _acme-challenge.{domain} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let token = self.get_token()?;
        let zone_id = self.get_zone_id(&token, domain)?;
        let record_name = format!("_acme-challenge.{domain}.");
        if let Ok(Some(id)) = self.get_recordset_id(&token, &zone_id, &record_name) {
            let _ = self
                .client
                .delete(format!("{DNS_API}/v2/zones/{zone_id}/recordsets/{id}"))
                .header("X-Auth-Token", &token)
                .send();
            println!("[huawei] TXT record removed: _acme-challenge.{domain}");
        }
        Ok(())
    }
}
