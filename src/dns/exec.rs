use anyhow::Result;
use std::process::Command;

use crate::dns::DnsProvider;

/// Exec DNS-01 provider: calls external scripts for present/cleanup.
/// Scripts receive domain and TXT value as arguments:
///   present.sh <domain> <txt_value>
///   clean.sh   <domain> <txt_value>
pub struct ExecDns {
    present_script: String,
    clean_script: String,
}

impl ExecDns {
    pub fn new(present_script: String, clean_script: String) -> Self {
        Self { present_script, clean_script }
    }
}

impl DnsProvider for ExecDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let output = Command::new(&self.present_script)
            .args([domain, value])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{}: {stderr}", self.present_script);
        }
        Ok(())
    }

    fn cleanup(&self, domain: &str, value: &str) -> Result<()> {
        let output = Command::new(&self.clean_script)
            .args([domain, value])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{}: {stderr}", self.clean_script);
        }
        Ok(())
    }
}
