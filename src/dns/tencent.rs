/// Tencent Cloud DNS (DNSPod API v3) provider.
///
/// Requires Tencent_SecretId and Tencent_SecretKey env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_tencent.sh
use anyhow::{anyhow, bail, Result};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dns::DnsProvider;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const TC_API: &str = "https://dnspod.tencentcloudapi.com";
const TC_SERVICE: &str = "dnspod";
const TC_VERSION: &str = "2021-03-23";

pub struct TencentDns {
    secret_id: String,
    secret_key: String,
    client: reqwest::blocking::Client,
}

impl TencentDns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            secret_id: env::var("Tencent_SecretId")
                .map_err(|_| anyhow!("Tencent_SecretId required"))?,
            secret_key: env::var("Tencent_SecretKey")
                .map_err(|_| anyhow!("Tencent_SecretKey required"))?,
            client: reqwest::blocking::Client::new(),
        })
    }

    fn sha256hex(data: &str) -> String {
        format!("{:x}", Sha256::digest(data.as_bytes()))
    }

    fn hmac_sign(key: &[u8], data: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC");
        mac.update(data.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    fn tc3_sign(&self, action: &str, payload: &str, timestamp: u64) -> String {
        let date = {
            let secs = timestamp;
            let days = secs / 86400;
            let d = days % 36525;
            let y = 1970 + d / 365;
            let dy = d % 365;
            let mo: &[(u64, u64)] = &[
                (31, 1),
                (59, 2),
                (90, 3),
                (120, 4),
                (151, 5),
                (181, 6),
                (212, 7),
                (243, 8),
                (273, 9),
                (304, 10),
                (334, 11),
                (365, 12),
            ];
            let mut m = 1u64;
            let mut day = 1u64;
            for (dm, mn) in mo {
                if dy < *dm {
                    m = *mn;
                    day = if m == 1 {
                        dy + 1
                    } else {
                        dy - mo
                            .iter()
                            .find(|(_, x)| *x == m - 1)
                            .map(|(d, _)| *d)
                            .unwrap_or(0)
                            + 1
                    };
                    break;
                }
            }
            format!("{y:04}-{m:02}-{day:02}")
        };

        let canonical_headers = format!("content-type:application/json\nhost:dnspod.tencentcloudapi.com\nx-tc-action:{action}\n");
        let signed_headers = "content-type;host;x-tc-action";
        let canonical = format!(
            "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{}",
            Self::sha256hex(payload)
        );
        let scope = format!("{date}/{TC_SERVICE}/tc3_request");
        let sts = format!(
            "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            Self::sha256hex(&canonical)
        );

        let k_date = Self::hmac_sign(format!("TC3{}", self.secret_key).as_bytes(), &date);
        let k_service = Self::hmac_sign(&k_date, TC_SERVICE);
        let k_signing = Self::hmac_sign(&k_service, "tc3_request");
        let sig = Self::hmac_sign(&k_signing, &sts);
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();

        format!("TC3-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig_hex}", self.secret_id)
    }

    fn call_api(&self, action: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
        let payload_str = serde_json::to_string(payload)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let auth = self.tc3_sign(action, &payload_str, ts);

        let resp: serde_json::Value = self
            .client
            .post(TC_API)
            .header("Authorization", &auth)
            .header("Content-Type", "application/json")
            .header("Host", "dnspod.tencentcloudapi.com")
            .header("X-TC-Action", action)
            .header("X-TC-Version", TC_VERSION)
            .header("X-TC-Timestamp", ts.to_string())
            .body(payload_str)
            .send()?
            .json()?;

        if let Some(err) = resp["Response"]["Error"].as_object() {
            bail!(
                "TencentCloud error: {}",
                err["Message"].as_str().unwrap_or("unknown")
            );
        }
        Ok(resp)
    }

    fn get_root_domain(&self, domain: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let sub = parts[..i].join(".");
            let payload = serde_json::json!({"Domain": &root, "Limit": 3000});
            if self.call_api("DescribeRecordFilterList", &payload).is_ok() {
                return Ok((root, sub));
            }
        }
        bail!("TencentCloud: domain not found for {domain}");
    }
}

impl DnsProvider for TencentDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub) = self.get_root_domain(domain)?;
        let payload = serde_json::json!({
            "Domain": root,
            "SubDomain": sub,
            "RecordType": "TXT",
            "RecordLineId": "0",
            "Value": value,
            "TTL": 600,
        });
        self.call_api("CreateRecord", &payload)?;
        println!("[tencent] TXT record set: _acme-challenge.{domain} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let (root, sub) = self.get_root_domain(domain)?;
        let payload = serde_json::json!({
            "Domain": root,
            "SubDomain": sub,
            "RecordValue": value,
        });
        if let Ok(resp) = self.call_api("DescribeRecordFilterList", &payload) {
            if let Some(records) = resp["Response"]["RecordList"].as_array() {
                for r in records {
                    if r["Name"].as_str() == Some(&sub) && r["Value"].as_str() == Some(value) {
                        if let Some(id) = r["RecordId"].as_u64() {
                            let dp = serde_json::json!({"Domain": root, "RecordId": id});
                            let _ = self.call_api("DeleteRecord", &dp);
                            println!("[tencent] TXT record removed: _acme-challenge.{domain}");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
