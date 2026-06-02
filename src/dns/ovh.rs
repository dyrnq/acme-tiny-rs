/// OVH DNS provider.
///
/// Requires OVH_APPLICATION_KEY (OVH_AK), OVH_APPLICATION_SECRET (OVH_AS),
/// and OVH_CONSUMER_KEY (OVH_CK) env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_ovh.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

const OVH_EU: &str = "https://eu.api.ovh.com/1.0";
const OVH_US: &str = "https://api.us.ovhcloud.com/1.0";
const OVH_CA: &str = "https://ca.api.ovh.com/1.0";
const KSF_EU: &str = "https://eu.api.kimsufi.com/1.0";
const KSF_CA: &str = "https://ca.api.kimsufi.com/1.0";
const SYS_EU: &str = "https://eu.api.soyoustart.com/1.0";
const SYS_CA: &str = "https://ca.api.soyoustart.com/1.0";

pub struct OvhDns {
    endpoint: String,
    app_key: String,
    app_secret: String,
    consumer_key: String,
    client: reqwest::blocking::Client,
}

impl OvhDns {
    pub fn new() -> Result<Self> {
        let app_key = env::var("OVH_APPLICATION_KEY")
            .or_else(|_| env::var("OVH_AK"))
            .map_err(|_| anyhow!("OVH_APPLICATION_KEY (or OVH_AK) env var required"))?;

        let app_secret = env::var("OVH_APPLICATION_SECRET")
            .or_else(|_| env::var("OVH_AS"))
            .map_err(|_| anyhow!("OVH_APPLICATION_SECRET (or OVH_AS) env var required"))?;

        let consumer_key = env::var("OVH_CONSUMER_KEY")
            .or_else(|_| env::var("OVH_CK"))
            .map_err(|_| anyhow!("OVH_CONSUMER_KEY (or OVH_CK) env var required"))?;

        let endpoint = env::var("OVH_ENDPOINT").unwrap_or_else(|_| "ovh-eu".to_string());

        Ok(Self {
            endpoint,
            app_key,
            app_secret,
            consumer_key,
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    fn base_url(&self) -> &str {
        match self.endpoint.as_str() {
            "ovh-eu" | "ovheu" => OVH_EU,
            "ovh-us" | "ovhus" => OVH_US,
            "ovh-ca" | "ovhca" => OVH_CA,
            "kimsufi-eu" | "kimsufieu" => KSF_EU,
            "kimsufi-ca" | "kimsufica" => KSF_CA,
            "soyoustart-eu" | "soyoustarteu" => SYS_EU,
            "soyoustart-ca" | "soyoustartca" => SYS_CA,
            raw if raw.starts_with("https://") => raw,
            other => other, // fallback - will likely fail at API call
        }
    }

    fn sign_request(&self, method: &str, url: &str, body: &str) -> String {
        use digest::Digest;
        use sha1::Sha1;

        let _now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let payload = format!(
            "{}+{}+{}+{}+{}",
            self.app_secret, self.consumer_key, method, url, body
        );

        let mut hasher = Sha1::new();
        hasher.update(payload.as_bytes());
        let result = hasher.finalize();
        let hash_hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();

        format!("${}${}", 1, hash_hex)
    }

    fn get_timestamp(&self) -> Result<String> {
        let url = format!("{}/auth/time", self.base_url());
        let resp = self.client.get(&url).send()?;
        Ok(resp.text()?.trim().to_string())
    }

    fn api_call(&self, method: &str, path: &str, body: &str) -> Result<String> {
        let base = self.base_url();
        // Remove trailing /1.0 from base if path starts with /
        let url = if path.starts_with('/') {
            // base is like https://.../1.0, path is like /domain/zone/...
            // We need to remove the /1.0 suffix
            let clean_base = base.strip_suffix("/1.0").unwrap_or(base);
            format!("{}/1.0{}", clean_base, path)
        } else {
            format!("{}/{}", base, path)
        };

        let timestamp = self.get_timestamp()?;
        let signature = self.sign_request(method, &url, body);

        let mut req = self.client.request(
            match method {
                "GET" => reqwest::Method::GET,
                "POST" => reqwest::Method::POST,
                "DELETE" => reqwest::Method::DELETE,
                "PUT" => reqwest::Method::PUT,
                _ => reqwest::Method::GET,
            },
            &url,
        );
        req = req
            .header("X-Ovh-Application", &self.app_key)
            .header("X-Ovh-Signature", &signature)
            .header("X-Ovh-Timestamp", &timestamp)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("Content-Type", "application/json;charset=utf-8");

        if !body.is_empty() || method == "POST" || method == "DELETE" || method == "PUT" {
            req = req.body(body.to_string());
        }

        let resp = req.send()?;
        let text = resp.text()?;

        if text.contains("INVALID_CREDENTIAL") || text.contains("NOT_CREDENTIAL") {
            bail!("OVH API authentication failed: {}", text);
        }
        if text.contains("NOT_GRANTED_CALL") {
            bail!("OVH API: call not granted (check permissions): {}", text);
        }
        if text.contains("This service does not exist") {
            bail!("OVH API: service does not exist at {}", url);
        }

        Ok(text)
    }

    fn find_zone(&self, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        let _prev_i = 1;

        for i in 1..=parts.len() {
            let zone = parts[i.saturating_sub(1)..].join(".");
            if zone.is_empty() {
                continue;
            }

            let resp = self.api_call("GET", &format!("/domain/zone/{}", zone), "")?;

            // Check if this is a valid zone (not an error)
            if !resp.contains("This service does not exist")
                && !resp.contains("This call has not been granted")
                && !resp.contains("NOT_GRANTED_CALL")
            {
                let sub = parts[..i.saturating_sub(1)].join(".");
                return Ok((zone, sub));
            }
        }

        bail!("No matching OVH zone found for {}", domain);
    }

    fn refresh_zone(&self, zone: &str) {
        let _ = self.api_call("POST", &format!("/domain/zone/{}/refresh", zone), "{}");
    }
}

impl DnsProvider for OvhDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{}", domain);
        let (zone, sub) = self.find_zone(&record_name)?;

        let body = serde_json::json!({
            "fieldType": "TXT",
            "subDomain": sub,
            "target": value,
            "ttl": 60
        });

        let resp = self.api_call(
            "POST",
            &format!("/domain/zone/{}/record", zone),
            &body.to_string(),
        )?;

        if resp.contains("INVALID_CREDENTIAL") || resp.contains("NOT_CREDENTIAL") {
            bail!("OVH API authentication failed: {}", resp);
        }

        self.refresh_zone(&zone);
        println!("[ovh] TXT record set: {record_name} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let record_name = format!("_acme-challenge.{}", domain);
        let (zone, sub) = match self.find_zone(&record_name) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        // List TXT records matching the subdomain
        let resp = self.api_call(
            "GET",
            &format!(
                "/domain/zone/{}/record?fieldType=TXT&subDomain={}",
                zone, sub
            ),
            "",
        )?;

        // Response is a JSON array of record IDs like [123456, 789012]
        let ids: Result<Vec<u64>, _> = serde_json::from_str(&resp);
        if let Ok(record_ids) = ids {
            for rid in record_ids {
                // Get the record details to check if it matches
                let detail =
                    self.api_call("GET", &format!("/domain/zone/{}/record/{}", zone, rid), "")?;
                if detail.contains(value) {
                    let _ = self.api_call(
                        "DELETE",
                        &format!("/domain/zone/{}/record/{}", zone, rid),
                        "",
                    );
                }
            }
            self.refresh_zone(&zone);
            println!("[ovh] TXT record removed: {record_name}");
        }
        Ok(())
    }
}
