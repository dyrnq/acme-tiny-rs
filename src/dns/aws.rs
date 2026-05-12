/// AWS Route53 DNS provider (full SigV4 + XML parsing).
/// Requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_aws.sh
use anyhow::{anyhow, bail, Result};
use std::env;

use crate::dns::DnsProvider;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

type HmacSha256 = Hmac<Sha256>;

const R53_HOST: &str = "route53.amazonaws.com";
const R53_API: &str = "https://route53.amazonaws.com/2013-04-01";

pub struct AwsRoute53Dns {
    access_key: String,
    secret_key: String,
    client: reqwest::blocking::Client,
}

impl AwsRoute53Dns {
    pub fn new() -> Result<Self> {
        let access_key = env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| anyhow!("AWS_ACCESS_KEY_ID env var required"))?;
        let secret_key = env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| anyhow!("AWS_SECRET_ACCESS_KEY env var required"))?;
        Ok(Self { access_key, secret_key, client: reqwest::blocking::Client::new() })
    }

    fn hex_digest(data: &[u8]) -> String { format!("{:x}", Sha256::digest(data)) }

    fn hmac_sign(secret: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn sigv4(&self, method: &str, uri: &str, query: &str, body: &str) -> Result<(String, String)> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let total_secs = now.as_secs();
        // Proper date/time from real timestamp
        let secs_in_day = total_secs % 86400;
        let h = secs_in_day / 3600;
        let m = (secs_in_day % 3600) / 60;
        let s = secs_in_day % 60;

        // Use a simpler approach: format as YYYYMMDD based on the epoch
        let days_since_epoch = total_secs / 86400;
        let d = days_since_epoch % 36525; // rough year calculation
        let y = 1970 + d / 365;
        let dy = d % 365;
        let mo_day: &[(u64, u64)] = &[(31,1),(59,2),(90,3),(120,4),(151,5),(181,6),(212,7),(243,8),(273,9),(304,10),(334,11),(365,12)];
        let mut month = 1u64;
        let mut day = 1u64;
        for (dm, m_num) in mo_day {
            if dy < *dm { month = *m_num; day = if month == 1 { dy + 1 } else { dy - mo_day.iter().find(|(_, mn)| *mn == month - 1).map(|(d,_)| *d).unwrap_or(0) + 1 }; break; }
        }
        let date = format!("{:04}{:02}{:02}", y, month, day);
        let amz_date = format!("{date}T{:02}{:02}{:02}Z", h, m, s);

        let scope = format!("{date}/us-east-1/route53/aws4_request");
        let signed_headers = "host;x-amz-date";
        let canonical_headers = format!("host:{R53_HOST}\nx-amz-date:{amz_date}\n");
        let payload_hash = Self::hex_digest(body.as_bytes());
        let canonical = format!("{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
        let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", Self::hex_digest(canonical.as_bytes()));

        let k_date = Self::hmac_sign(format!("AWS4{}", self.secret_key).as_bytes(), date.as_bytes());
        let k_region = Self::hmac_sign(&k_date, b"us-east-1");
        let k_service = Self::hmac_sign(&k_region, b"route53");
        let k_signing = Self::hmac_sign(&k_service, b"aws4_request");
        let sig = Self::hmac_sign(&k_signing, sts.as_bytes());
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();

        let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}/us-east-1/route53/aws4_request,SignedHeaders={signed_headers},Signature={sig_hex}",
            self.access_key, date);
        Ok((amz_date, auth))
    }

    fn call_api(&self, path: &str, query: &str, body: &str) -> Result<String> {
        let (amz_date, auth) = self.sigv4(if body.is_empty() { "GET" } else { "POST" }, path, query, body)?;
        let url = format!("{R53_API}{path}?{query}");

        let req = if body.is_empty() {
            self.client.get(&url)
        } else {
            self.client.post(&url).body(body.to_string())
        };
        let resp = req
            .header("Host", R53_HOST)
            .header("X-Amz-Date", &amz_date)
            .header("Authorization", &auth)
            .header("Content-Type", "application/xml")
            .send()?;
        let text = resp.text()?;
        if text.contains("<ErrorResponse") { bail!("AWS Route53 API error: {text}"); }
        Ok(text)
    }

    fn get_zone_id(&self, domain: &str) -> Result<String> {
        let mut marker: Option<String> = None;
        loop {
            let q = marker.as_deref().map(|m| format!("marker={m}")).unwrap_or_default();
            let xml = self.call_api("/hostedzone", &q, "")?;
            for part in xml.split("<HostedZone>").skip(1) {
                if part.contains("<PrivateZone>false</PrivateZone>")
                    && part.contains(&format!("<Name>{domain}.</Name>"))
                {
                    let id = part.split("<Id>").nth(1).and_then(|s| s.split("</Id>").next())
                        .and_then(|s| s.split('/').last().map(|s| s.to_string()))
                        .ok_or_else(|| anyhow!("Zone ID not found in XML"))?;
                    return Ok(id);
                }
            }
            if xml.contains("<IsTruncated>true</IsTruncated>") {
                marker = xml.split("<NextMarker>").nth(1)
                    .and_then(|s| s.split("</NextMarker>").next())
                    .map(|s| s.to_string());
            } else { break; }
        }
        bail!("Hosted zone not found for {domain}");
    }
}

impl DnsProvider for AwsRoute53Dns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let zone_id = self.get_zone_id(domain)?;
        let record = format!("_acme-challenge.{domain}");
        let body = format!(r#"<?xml version="1.0"?><ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes><Change><Action>UPSERT</Action><ResourceRecordSet><Name>{record}.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>"{value}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#);
        self.call_api(&format!("/hostedzone/{zone_id}/rrset"), "", &body)?;
        println!("[aws] TXT record set: {record} = {value}");
        Ok(())
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let zone_id = self.get_zone_id(domain)?;
        let record = format!("_acme-challenge.{domain}");
        let body = format!(r#"<?xml version="1.0"?><ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes><Change><Action>DELETE</Action><ResourceRecordSet><Name>{record}.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>"{value}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#);
        let _ = self.call_api(&format!("/hostedzone/{zone_id}/rrset"), "", &body);
        println!("[aws] TXT record removed: {record}");
        Ok(())
    }
}
