//! Shell completion script generation.
//!
//! Usage: `acme-tiny-rs completions bash > /usr/share/bash-completion/completions/acme-tiny-rs`

use anyhow::{bail, Result};
use clap::{CommandFactory, ValueHint};
use clap_complete::{generate, Shell};

use crate::Cli;

pub fn run(shell: &str) -> Result<()> {
    let sh = match shell {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" => Shell::PowerShell,
        _ => bail!("Unsupported shell: {shell}. Use bash, zsh, fish, or powershell."),
    };
    let mut cmd = Cli::command();
    generate(sh, &mut cmd, "acme-tiny-rs", &mut std::io::stdout());
    Ok(())
}
