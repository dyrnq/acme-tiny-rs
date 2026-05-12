/// DNSPod DNS API provider (Tencent Cloud).
///
/// Requires DP_Id and DP_Key env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_dp.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;

const DP_API: &str = "https://dnsapi.cn";

pub struct DNSPodDns {
    id: String,
    key: String,
    client: reqwest::blocking::Client,
}

impl DNSPodDns {
    pub fn new() -> Result<Self> {
        let id = env::var("DP_Id").map_err(|_| anyhow!("DP_Id env var required"))?;
        let key = env::var("DP_Key").map_err(|_| anyhow!("DP_Key env var required"))?;
        Ok(Self { id, key, client: reqwest::blocking::Client::new() })
    }

    fn call_api(&self, action: &str, extra: &[(&str, &str)]) -> Result<serde_json::Value> {
        let login = format!("{},{}", self.id, self.key);
        let mut body: Vec<(&str, &str)> = vec![
            ("login_token", &login),
            ("format", "json"),
            ("lang", "cn"),
            ("error_on_empty", "no"),
        ];
        body.extend_from_slice(extra);
        let resp: serde_json::Value = self.client
            .post(format!("{DP_API}/{action}"))
            .form(&body)
            .send()?
            .json()?;
        if resp["status"]["code"].as_str() != Some("1") {
            let msg = resp["status"]["message"].as_str().unwrap_or("unknown error");
            bail!("DNSPod API error: {msg}");
        }
        Ok(resp)
    }

    fn get_root_domain(&self, domain: &str) -> Result<(String, String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            // Use Domain.Info to check if this is the root domain
            let resp = self.call_api("Domain.Info", &[("domain", &root)]);
            if resp.is_ok() {
                if let Ok(r) = resp {
                    if let Some(domain_info) = r["domain"].as_object() {
                        if let Some(id) = domain_info.get("id").and_then(|v| v.as_str()) {
                            return Ok((root, sub, id.to_string()));
                        }
                    }
                }
            }
        }
        bail!("Cannot find root domain for {domain}");
    }
}

impl DnsProvider for DNSPodDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (_root, sub, domain_id) = self.get_root_domain(domain)?;
        self.call_api("Record.Create", &[
            ("domain_id", &domain_id),
            ("sub_domain", &sub),
            ("record_type", "TXT"),
            ("record_line", "默认"),
            ("value", value),
        ])?;
        println!("[dnspod] TXT record set: _acme-challenge.{domain} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let (_root, sub, domain_id) = self.get_root_domain(domain)?;
        if let Ok(resp) = self.call_api("Record.List", &[
            ("domain_id", &domain_id),
            ("sub_domain", &sub),
            ("record_type", "TXT"),
        ]) {
            if let Some(records) = resp["records"].as_array() {
                for r in records {
                    if r["value"].as_str() == Some(value) {
                        if let Some(id) = r["id"].as_str() {
                            let _ = self.call_api("Record.Remove", &[
                                ("domain_id", &domain_id),
                                ("record_id", id),
                            ]);
                            println!("[dnspod] TXT record removed: _acme-challenge.{domain}");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
