/// Azure DNS provider.
/// Requires AZUREDNS_SUBSCRIPTIONID and AZUREDNS_TENANTID, AZUREDNS_APPID, AZUREDNS_CLIENTSECRET.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_azure.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

pub struct AzureDns {
    subscription_id: String,
    tenant_id: Option<String>,
    app_id: Option<String>,
    client_secret: Option<String>,
    client: reqwest::blocking::Client,
}

impl AzureDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            subscription_id: env::var("AZUREDNS_SUBSCRIPTIONID")
                .map_err(|_| anyhow!("AZUREDNS_SUBSCRIPTIONID required"))?,
            tenant_id: env::var("AZUREDNS_TENANTID").ok(),
            app_id: env::var("AZUREDNS_APPID").ok(),
            client_secret: env::var("AZUREDNS_CLIENTSECRET").ok(),
            client: reqwest::blocking::Client::new(),
        })
    }

    fn get_token(&self) -> Result<String> {
        // Return bearer token if provided directly
        if let Ok(tok) = env::var("AZUREDNS_BEARERTOKEN") {
            return Ok(tok);
        }
        let tenant = self.tenant_id.as_deref().ok_or_else(|| anyhow!("AZUREDNS_TENANTID required"))?;
        let app = self.app_id.as_deref().ok_or_else(|| anyhow!("AZUREDNS_APPID required"))?;
        let secret = self.client_secret.as_deref().ok_or_else(|| anyhow!("AZUREDNS_CLIENTSECRET required"))?;

        let resp: serde_json::Value = self.client
            .post(format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", app),
                ("client_secret", secret),
                ("scope", "https://management.azure.com/.default"),
            ])
            .send()?
            .json()?;
        resp["access_token"].as_str().map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Failed to get Azure token: {resp}"))
    }

    /// Find DNS zone and resource group for domain.
    /// acme-sh uses the zone name itself as resource group (default ARM naming).
    fn find_zone(&self, domain: &str, token: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let url = format!(
                "https://management.azure.com/subscriptions/{}/providers/Microsoft.Network/dnsZones/{}?api-version=2018-05-01",
                self.subscription_id, root
            );
            let resp = self.client.get(&url)
                .header("Authorization", format!("Bearer {token}"))
                .send()?;
            if resp.status().is_success() {
                let zone: serde_json::Value = resp.json()?;
                // Resource group is in the zone id: .../resourceGroups/{rg}/...
                let rg = zone["id"].as_str()
                    .and_then(|id| id.split("resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or(&root);
                return Ok((rg.to_string(), sub));
            }
        }
        bail!("DNS zone not found for {domain}");
    }
}

impl DnsProvider for AzureDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let token = self.get_token()?;
        let (rg, sub) = self.find_zone(domain, &token)?;
        let parts: Vec<&str> = domain.split('.').collect();
        let root = parts[1..].join(".");
        let record_name = if sub.is_empty() { "_acme-challenge".to_string() }
            else { format!("_acme-challenge.{sub}") };

        let body = serde_json::json!({
            "properties": { "TTL": 60, "TXTRecords": [{"value": [value]}] }
        });
        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id, rg, root, record_name
        );
        let resp = self.client.put(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Azure DNS error: {}", resp.text().unwrap_or_default());
        }
        println!("[azure] TXT record set: _acme-challenge.{domain} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let token = self.get_token()?;
        let (rg, sub) = self.find_zone(domain, &token)?;
        let parts: Vec<&str> = domain.split('.').collect();
        let root = parts[1..].join(".");
        let record_name = if sub.is_empty() { "_acme-challenge".to_string() }
            else { format!("_acme-challenge.{sub}") };

        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id, rg, root, record_name
        );
        let resp = self.client.delete(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()?;
        if resp.status().is_success() || resp.status().as_u16() == 204 {
            println!("[azure] TXT record removed: _acme-challenge.{domain}");
        }
        Ok(())
    }
}
