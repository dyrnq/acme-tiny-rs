/// Google Cloud DNS provider.
///
/// Requires `gcloud` CLI to be installed and authenticated.
/// Uses `gcloud dns record-sets` commands for DNS management.
/// Reference: https://github.com/acmesh-official/acme.sh/tree/master/dnsapi/dns_gcloud.sh
use anyhow::{anyhow, bail, Result};
use std::env;
use std::process::Command;

use crate::dns::DnsProvider;

#[allow(dead_code)]
pub struct GoogleCloudDns {
    zone_name: Option<String>,
}

impl GoogleCloudDns {
    pub fn new() -> Result<Self> {
        env::var("GCE_PROJECT")
            .map_err(|_| anyhow!("GCE_PROJECT env var required (Google Cloud project ID)"))?;

        // Verify gcloud is available
        let output = Command::new("gcloud")
            .arg("--version")
            .output()
            .map_err(|e| {
                anyhow!(
                    "gcloud CLI not found: {}. Install it or use another DNS provider.",
                    e
                )
            })?;

        if !output.status.success() {
            bail!(
                "gcloud CLI failed to run: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(Self { zone_name: None })
    }

    fn find_zone(&self, domain: &str) -> Result<String> {
        let project = env::var("GCE_PROJECT").unwrap();

        // Walk up domain parts to find matching managed zone
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let dns_name = parts[i..].join(".");
            let output = Command::new("gcloud")
                .args([
                    "dns",
                    "managed-zones",
                    "list",
                    "--project",
                    &project,
                    "--format=value(name)",
                    "--filter",
                    &format!("dnsName={} AND visibility=public", dns_name),
                ])
                .output()?;

            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return Ok(name);
                }
            }
        }

        bail!("No matching public managed zone found for {}", domain);
    }

    fn find_existing_records(&self, domain: &str) -> Result<Vec<String>> {
        let project = env::var("GCE_PROJECT").unwrap();
        let zone = self.find_zone(domain)?;
        let record_name = format!("_acme-challenge.{}.", domain);

        let output = Command::new("gcloud")
            .args([
                "dns",
                "record-sets",
                "list",
                "--zone",
                &zone,
                "--project",
                &project,
                "--name",
                &record_name,
                "--type=TXT",
                "--format=value(rrdatas)",
            ])
            .output()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            Ok(text
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect())
        } else {
            Ok(vec![])
        }
    }
}

impl DnsProvider for GoogleCloudDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let project = env::var("GCE_PROJECT").unwrap();
        let zone = self.find_zone(&format!("_acme-challenge.{}", domain))?;
        let record_name = format!("_acme-challenge.{}.", domain);

        // Build the transaction
        let output = Command::new("gcloud")
            .args([
                "dns",
                "record-sets",
                "transaction",
                "start",
                "--zone",
                &zone,
                "--project",
                &project,
            ])
            .output()?;

        if !output.status.success() {
            bail!(
                "gcloud transaction start failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Remove existing records (if any)
        let existing = self.find_existing_records(domain)?;
        if !existing.is_empty() {
            let mut args = vec![
                "dns".to_string(),
                "record-sets".to_string(),
                "transaction".to_string(),
                "remove".to_string(),
                "--name".to_string(),
                record_name.clone(),
                "--ttl".to_string(),
                "60".to_string(),
                "--type".to_string(),
                "TXT".to_string(),
                "--zone".to_string(),
                zone.clone(),
                "--project".to_string(),
                project.clone(),
                "--".to_string(),
            ];
            args.extend(existing);
            let output = Command::new("gcloud").args(&args).output()?;
            if !output.status.success() {
                let _ = Command::new("gcloud")
                    .args([
                        "dns",
                        "record-sets",
                        "transaction",
                        "abort",
                        "--zone",
                        &zone,
                        "--project",
                        &project,
                    ])
                    .output();
                bail!(
                    "gcloud transaction remove failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Add new record
        let output = Command::new("gcloud")
            .args([
                "dns",
                "record-sets",
                "transaction",
                "add",
                "--name",
                &record_name,
                "--ttl",
                "60",
                "--type",
                "TXT",
                "--zone",
                &zone,
                "--project",
                &project,
                "--",
                &format!("\"{}\"", value),
            ])
            .output()?;

        if !output.status.success() {
            let _ = Command::new("gcloud")
                .args([
                    "dns",
                    "record-sets",
                    "transaction",
                    "abort",
                    "--zone",
                    &zone,
                    "--project",
                    &project,
                ])
                .output();
            bail!(
                "gcloud transaction add failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Execute transaction
        let output = Command::new("gcloud")
            .args([
                "dns",
                "record-sets",
                "transaction",
                "execute",
                "--zone",
                &zone,
                "--project",
                &project,
            ])
            .output()?;

        if !output.status.success() {
            bail!(
                "gcloud transaction execute failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        println!(
            "[gcloud] TXT record set: _acme-challenge.{} = {}",
            domain, value
        );
        Ok(())
    }

    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let project = env::var("GCE_PROJECT").unwrap();
        let record_name = format!("_acme-challenge.{}.", domain);
        let zone = match self.find_zone(&format!("_acme-challenge.{}", domain)) {
            Ok(z) => z,
            Err(_) => return Ok(()),
        };

        // Start transaction
        let output = Command::new("gcloud")
            .args([
                "dns",
                "record-sets",
                "transaction",
                "start",
                "--zone",
                &zone,
                "--project",
                &project,
            ])
            .output()?;

        if !output.status.success() {
            return Ok(()); // Zone may not exist anymore, skip cleanup
        }

        // Remove records
        let existing = match self.find_existing_records(domain) {
            Ok(r) => r,
            Err(_) => {
                let _ = Command::new("gcloud")
                    .args([
                        "dns",
                        "record-sets",
                        "transaction",
                        "abort",
                        "--zone",
                        &zone,
                        "--project",
                        &project,
                    ])
                    .output();
                return Ok(());
            }
        };

        if !existing.is_empty() {
            let mut args = vec![
                "dns".to_string(),
                "record-sets".to_string(),
                "transaction".to_string(),
                "remove".to_string(),
                "--name".to_string(),
                record_name.clone(),
                "--ttl".to_string(),
                "60".to_string(),
                "--type".to_string(),
                "TXT".to_string(),
                "--zone".to_string(),
                zone.clone(),
                "--project".to_string(),
                project.clone(),
                "--".to_string(),
            ];
            args.extend(existing);
            let output = Command::new("gcloud").args(&args).output()?;
            if output.status.success() {
                // Execute transaction
                let _ = Command::new("gcloud")
                    .args([
                        "dns",
                        "record-sets",
                        "transaction",
                        "execute",
                        "--zone",
                        &zone,
                        "--project",
                        &project,
                    ])
                    .output();
                println!("[gcloud] TXT record removed: _acme-challenge.{}", domain);
            } else {
                let _ = Command::new("gcloud")
                    .args([
                        "dns",
                        "record-sets",
                        "transaction",
                        "abort",
                        "--zone",
                        &zone,
                        "--project",
                        &project,
                    ])
                    .output();
            }
        } else {
            let _ = Command::new("gcloud")
                .args([
                    "dns",
                    "record-sets",
                    "transaction",
                    "abort",
                    "--zone",
                    &zone,
                    "--project",
                    &project,
                ])
                .output();
        }

        Ok(())
    }
}
