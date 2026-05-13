//! `version` subcommand — print version, git hash, and build timestamp.

use anyhow::Result;

pub fn run() -> Result<()> {
    println!(
        "{} v{} ({}, {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH"),
        env!("BUILD_TIME"),
    );
    Ok(())
}
