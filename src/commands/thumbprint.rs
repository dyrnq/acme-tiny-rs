//! `thumbprint` subcommand — compute JWK thumbprint (RFC 7638).
//! Outputs the base64url-encoded SHA-256 of the canonical JWK JSON,
//! used for stateless HTTP-01 and dns-account-01 challenges.

use anyhow::{Context, Result};
use std::io::Read;

use crate::parse_account_key;

pub fn run(account_key_path: &str) -> Result<()> {
    let signing_key = if account_key_path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .with_context(|| "Failed to read account key from stdin")?;
        // parse PEM from string — detect key type manually
        crate::parse_account_key_bytes(&buf)?
    } else {
        parse_account_key(account_key_path)?
    };
    let jwk = signing_key.jwk();
    let canonical = crate::canonical_jwk_json(jwk)?;
    use sha2::Digest;
    let thumbprint = crate::b64(&sha2::Sha256::digest(canonical.as_bytes()));
    println!("{thumbprint}");
    Ok(())
}
