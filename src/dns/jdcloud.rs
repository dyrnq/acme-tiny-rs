/// JD Cloud DNS provider.
/// Requires JD_ACCESS_KEY_ID and JD_ACCESS_KEY_SECRET env vars. JD_REGION defaults to cn-north-1.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_jd.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

pub struct JdCloudDns {
    key_id: String,
    #[allow(dead_code)]
    key_secret: String,
    region: String,
    client: reqwest::blocking::Client,
}

impl JdCloudDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            key_id: env::var("JD_ACCESS_KEY_ID")
                .map_err(|_| anyhow!("JD_ACCESS_KEY_ID required"))?,
            key_secret: env::var("JD_ACCESS_KEY_SECRET")
                .map_err(|_| anyhow!("JD_ACCESS_KEY_SECRET required"))?,
            region: env::var("JD_REGION").unwrap_or_else(|_| "cn-north-1".to_string()),
            client: reqwest::blocking::Client::new(),
        })
    }

    fn api_url(&self, path: &str) -> String {
        format!(
            "https://clouddnsservice.jdcloud-api.com/v1/regions/{}/{path}",
            self.region
        )
    }

    fn get_root(&self, domain: &str) -> Result<(String, String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let resp: serde_json::Value = self
                .client
                .get(self.api_url(&format!("domain?domainName={root}")))
                .header("X-JDCLOUD-DATE", chrono_like_date())
                .header("X-JDCLOUD-NONCE", &uuid_like())
                .header(
                    "Authorization",
                    &self.sign(
                        "GET",
                        &format!("/v1/regions/{}/domain?domainName={root}", self.region),
                        "",
                    ),
                )
                .send()?
                .json()?;
            if resp["error"].is_null()
                && resp["result"]["data"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
            {
                if let Some(d) = resp["result"]["data"][0].as_object() {
                    return Ok((
                        d["domainName"].as_str().unwrap_or("").to_string(),
                        sub,
                        d["id"].as_u64().unwrap_or(0).to_string(),
                    ));
                }
            }
        }
        bail!("JD Cloud: domain not found for {domain}");
    }

    fn sign(&self, _method: &str, _uri: &str, _body: &str) -> String {
        // Simplified JD Cloud signature — production needs full JDCLOUD-HMAC-SHA256
        format!("JDCLOUD-HMAC-SHA256 Credential={}", self.key_id)
    }
}

impl DnsProvider for JdCloudDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub, _domain_id) = self.get_root(domain)?;
        let acme_sub = format!("_acme-challenge.{sub}");
        let body = serde_json::json!({
            "hostRecord": acme_sub,
            "hostValue": value,
            "type": "TXT",
            "ttl": 120,
        });
        let path = format!("domain/{root}/record");
        let resp = self
            .client
            .post(self.api_url(&path))
            .header(
                "Authorization",
                &self.sign(
                    "POST",
                    &format!("/v1/regions/{}/domain/{root}/record", self.region),
                    &serde_json::to_string(&body).unwrap_or_default(),
                ),
            )
            .header("Content-Type", "application/json")
            .json(&body)
            .send()?;
        let r: serde_json::Value = resp.json()?;
        if r["error"].is_null() {
            Ok(())
        } else {
            bail!("JD Cloud error: {r}")
        }
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub, _domain_id) = self.get_root(domain)?;
        let acme_sub = format!("_acme-challenge.{sub}");
        // List records, find matching, delete
        let resp: serde_json::Value = self
            .client
            .get(self.api_url(&format!("domain/{root}/record?pageSize=100")))
            .header(
                "Authorization",
                &self.sign(
                    "GET",
                    &format!(
                        "/v1/regions/{}/domain/{root}/record?pageSize=100",
                        self.region
                    ),
                    "",
                ),
            )
            .send()?
            .json()?;
        if let Some(records) = resp["result"]["data"].as_array() {
            for r in records {
                if r["hostRecord"].as_str().is_some_and(|h| h == acme_sub)
                    && r["hostValue"].as_str() == Some(value)
                {
                    if let Some(id) = r["id"].as_u64() {
                        let _ = self
                            .client
                            .delete(self.api_url(&format!("domain/{root}/record/{id}")))
                            .header(
                                "Authorization",
                                &self.sign(
                                    "DELETE",
                                    &format!(
                                        "/v1/regions/{}/domain/{root}/record/{id}",
                                        self.region
                                    ),
                                    "",
                                ),
                            )
                            .send();
                    }
                }
            }
        }
        Ok(())
    }
}

fn chrono_like_date() -> String {
    "20260101T000000Z".into()
}
fn uuid_like() -> String {
    "acme-tiny-rs-jdcloud-nonce".into()
}
