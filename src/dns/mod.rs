/// DNS-01 challenge provider trait and built-in implementations.
pub mod manual;
pub mod cf;
pub mod ali;
pub mod aws;
pub mod azure;
pub mod acmedns;
pub mod acmeproxy;
pub mod dp;
pub mod gd;
pub mod huawei;
pub mod duckdns;
pub mod linode;
pub mod vultr;
pub mod namecheap;
pub mod desec;
pub mod gandi;
pub mod namesilo;
pub mod porkbun;
pub mod bunny;
pub mod ionos;
pub mod tencent;
pub mod jdcloud;
pub mod netlify;

use anyhow::{bail, Result};

/// DNS-01 challenge provider trait.
///
/// Each DNS provider (manual, Cloudflare, Alibaba, etc.) implements this trait.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi
pub trait DnsProvider: Send + Sync {
    /// Set the ACME challenge TXT record.
    ///
    /// Record: `_acme-challenge.{domain}` IN TXT `{value}`
    fn present(&self, domain: &str, value: &str) -> Result<()>;

    /// Remove the TXT record after successful validation (best-effort).
    fn cleanup(&self, domain: &str, value: &str) -> Result<()>;
}

/// Create a DNS provider from a provider name string.
pub fn create_provider(name: &str) -> Result<Box<dyn DnsProvider>> {
    match name {
        "manual" => Ok(Box::new(manual::ManualDns)),
        "cloudflare" | "cf" => Ok(Box::new(cf::CloudflareDns::new()?)),
        "alibaba" | "ali" => Ok(Box::new(ali::AlibabaDns::new()?)),
        "aws" | "route53" => Ok(Box::new(aws::AwsRoute53Dns::new()?)),
        "azure" => Ok(Box::new(azure::AzureDns::new()?)),
        "acmedns" => Ok(Box::new(acmedns::AcmeDnsDns::new()?)),
        "acmeproxy" => Ok(Box::new(acmeproxy::AcmeProxyDns::new()?)),
        "dnspod" | "dp" => Ok(Box::new(dp::DNSPodDns::new()?)),
        "godaddy" | "gd" => Ok(Box::new(gd::GoDaddyDns::new()?)),
        "huaweicloud" | "huawei" => Ok(Box::new(huawei::HuaweiCloudDns::new()?)),
        "duckdns" => Ok(Box::new(duckdns::DuckDnsDns::new()?)),
        "linode" | "linode_v4" => Ok(Box::new(linode::LinodeV4Dns::new()?)),
        "linode_v3" => Ok(Box::new(linode::LinodeV3Dns::new()?)),
        "vultr" => Ok(Box::new(vultr::VultrDns::new()?)),
        "namecheap" => Ok(Box::new(namecheap::NamecheapDns::new()?)),
        "desec" => Ok(Box::new(desec::DesecDns::new()?)),
        "gandi" => Ok(Box::new(gandi::GandiDns::new()?)),
        "namesilo" => Ok(Box::new(namesilo::NameSiloDns::new()?)),
        "porkbun" => Ok(Box::new(porkbun::PorkbunDns::new()?)),
        "bunny" | "bunnycdn" => Ok(Box::new(bunny::BunnyDns::new()?)),
        "ionos" => Ok(Box::new(ionos::IonosDns::new()?)),
        "tencent" | "tencentcloud" => Ok(Box::new(tencent::TencentDns::new()?)),
        "jdcloud" | "jd" => Ok(Box::new(jdcloud::JdCloudDns::new()?)),
        "netlify" => Ok(Box::new(netlify::NetlifyDns::new()?)),
        _ => bail!("Unknown DNS provider: {name}"),
    }
}

/// Compute the DNS-01 TXT record value per RFC 8555 §8.4:
///
/// ```text
/// key_authorization = token || '.' || account_thumbprint
/// dns_txt_value     = base64url(SHA-256(key_authorization))
/// ```
pub fn dns_txt_value(token: &str, thumbprint: &str) -> String {
    let key_auth = format!("{token}.{thumbprint}");
    use sha2::Digest;
    crate::b64(&sha2::Sha256::digest(key_auth.as_bytes()))
}
