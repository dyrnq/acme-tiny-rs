//! ACME hook system — compatible with acme.sh hook semantics.
//!
//! Each hook is either a shell command (`--pre-hook "systemctl reload nginx"`)
//! or a path to an executable script (`--deploy-hook /etc/acme/deploy.sh`).
//! Hooks receive certificate metadata via environment variables.
//!
//! Reference: https://github.com/acmesh-official/acme.sh

use anyhow::{Context, Result};
use std::process::Command;

/// All supported hook types.
#[derive(Clone)]
pub enum Hook {
    /// Run before obtaining any certificates.
    Pre(String),
    /// Run after attempting to obtain/renew — regardless of success/failure.
    Post(String),
    /// Run after each successfully renewed certificate.
    Renew(String),
    /// Run after certificate issuance to deploy (e.g., copy to service, reload).
    Deploy(String),
    /// Run for notifications (email, webhook, etc.).
    Notify(String),
}

impl Hook {
    /// Execute the hook command or script with the given environment variables.
    pub fn run(&self, env_vars: &[(&str, &str)]) -> Result<()> {
        let cmd_str = match self {
            Hook::Pre(s) | Hook::Post(s) | Hook::Renew(s) | Hook::Deploy(s) | Hook::Notify(s) => s,
        };

        if cmd_str.is_empty() {
            return Ok(());
        }

        // Pick shell: sh on Unix, cmd on Windows
        let (shell, flag) = if cfg!(windows) {
            ("cmd", "/C")
        } else {
            ("sh", "-c")
        };

        println!("[hook] Running: {cmd_str}");
        let mut child = Command::new(shell)
            .arg(flag)
            .arg(cmd_str)
            .envs(env_vars.iter().copied())
            .spawn()
            .with_context(|| format!("Failed to execute hook: {cmd_str}"))?;

        let status = child.wait()?;
        if !status.success() {
            eprintln!(
                "[hook] Warning: '{cmd_str}' exited with code {}",
                status.code().unwrap_or(-1)
            );
        }
        Ok(())
    }

    /// Standard ACME environment variables set for all hooks (acme.sh compatible).
    pub fn acme_env_vars<'a>(
        cert_path: &'a str,
        key_path: &'a str,
        domain: &'a str,
    ) -> Vec<(&'a str, &'a str)> {
        vec![
            ("CERT_PATH", cert_path),
            ("Le_CertFile", cert_path),
            ("KEY_PATH", key_path),
            ("Le_KeyFile", key_path),
            ("Le_Domain", domain),
        ]
    }
}
