use anyhow::Result;

use crate::dns::DnsProvider;

/// Manual DNS-01 provider: prints the TXT record and waits for user confirmation.
pub struct ManualDns;

impl DnsProvider for ManualDns {
    fn present(&self, domain: &str, value: &str) -> Result<()> {
        let record = format!("_acme-challenge.{domain}");
        println!(
            "\n=== DNS-01 Challenge ===\n\
             Set the following TXT record:\n\n\
             \x1b[1m{record}\x1b[0m  IN  TXT  \x1b[1m{value}\x1b[0m\n\n\
             Press Enter after setting the DNS record..."
        );
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;
        Ok(())
    }

    fn cleanup(&self, domain: &str, _value: &str) -> Result<()> {
        let record = format!("_acme-challenge.{domain}");
        println!(
            "\n=== Cleanup ===\n\
             You may now remove this TXT record:\n\n\
             \x1b[1m{record}\x1b[0m"
        );
        Ok(())
    }
}
