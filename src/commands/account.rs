//! `account` subcommand — manage ACME account lifecycle.
//! Subcommands: show, update, register, unregister

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use crate::{b64, send_signed_request, Directory, SigningKey, USER_AGENT};

fn client(cb: Option<&str>, ins: bool) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder();
    if ins { b = b.danger_accept_invalid_certs(true); }
    else if let Some(p) = cb {
        b = b.add_root_certificate(reqwest::tls::Certificate::from_pem(&std::fs::read(p)?)?);
    }
    b.build().context("http client")
}

async fn kid(c: &reqwest::Client, sk: &SigningKey, du: &str) -> Result<(Directory, String)> {
    let d: serde_json::Value = c.get(du).header("User-Agent", USER_AGENT).send().await?.json().await?;
    let dir: Directory = serde_json::from_value(d).context("dir parse")?;
    let (_, _, hdr) = send_signed_request(c, &dir.new_account,
        Some(&json!({"termsOfServiceAgreed":true})), "lookup", sk, &None, &dir).await?;
    let loc = hdr.get("Location").and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("not registered"))?.to_string();
    Ok((dir, loc))
}

pub async fn show(sk: &SigningKey, du: &str, cb: Option<&str>, ins: bool, v: u8) -> Result<()> {
    let c = client(cb, ins)?; let (dir, k) = kid(&c, sk, du).await?;
    if v >= 2 { eprintln!("[account] GET {}", k); }
    let (info, _, _) = send_signed_request(&c, &k, None, "show", sk, &Some(k.clone()), &dir).await?;
    println!("{}", serde_json::to_string_pretty(&info)?); Ok(())
}

pub async fn update(sk: &SigningKey, du: &str, email: Option<&[String]>, cb: Option<&str>, ins: bool, v: u8) -> Result<()> {
    let c = client(cb, ins)?; let (dir, k) = kid(&c, sk, du).await?;
    if v >= 2 { eprintln!("[account] POST {}", k); }
    let mut p = json!({});
    if let Some(e) = email { p["contact"] = e.iter().map(|x| format!("mailto:{x}")).collect::<Vec<_>>().into(); }
    let (info, _, _) = send_signed_request(&c, &k, Some(&p), "update", sk, &Some(k.clone()), &dir).await?;
    println!("{}", serde_json::to_string_pretty(&info)?); Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn register(
    sk: &SigningKey, du: &str, email: Option<&[String]>, tos: bool,
    ek: Option<&str>, ehk: Option<&str>, eha: &str, cb: Option<&str>, ins: bool, v: u8,
) -> Result<()> {
    let c = client(cb, ins)?;
    let d: serde_json::Value = c.get(du).header("User-Agent", USER_AGENT).send().await?.json().await?;
    let dir: Directory = serde_json::from_value(d).context("dir parse")?;
    let mut p = json!({"termsOfServiceAgreed": tos});
    if let Some(e) = email { p["contact"] = e.iter().map(|x| format!("mailto:{x}")).collect::<Vec<_>>().into(); }
    if let (Some(kid), Some(hk)) = (ek, ehk) {
        let jwk = sk.jwk();
        let prot = json!({"alg": eha, "kid": kid, "url": dir.new_account});
        let p64 = b64(serde_json::to_string(&prot)?.as_bytes());
        let pl64 = b64(serde_json::to_string(jwk)?.as_bytes());
        let si = format!("{p64}.{pl64}");
        use base64::Engine;
        let dk = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(hk.as_bytes()).context("eab key")?;
        use hmac::{Hmac, Mac};
        let sig: Vec<u8> = match eha {
            "HS256" => { let mut m = Hmac::<sha2::Sha256>::new_from_slice(&dk)?; m.update(si.as_bytes()); m.finalize().into_bytes().to_vec() }
            "HS384" => { let mut m = Hmac::<sha2::Sha384>::new_from_slice(&dk)?; m.update(si.as_bytes()); m.finalize().into_bytes().to_vec() }
            "HS512" => { let mut m = Hmac::<sha2::Sha512>::new_from_slice(&dk)?; m.update(si.as_bytes()); m.finalize().into_bytes().to_vec() }
            _ => anyhow::bail!("unsupported eab alg: {eha}"),
        };
        p["externalAccountBinding"] = json!({"protected": p64, "payload": pl64, "signature": b64(&sig)});
    }
    if v >= 2 { eprintln!("[account] POST {}", dir.new_account); }
    let (info, _, hdr) = send_signed_request(&c, &dir.new_account, Some(&p), "register", sk, &None, &dir).await?;
    let loc = hdr.get("Location").and_then(|v| v.to_str().ok()).unwrap_or("(no location)");
    println!("Account URL: {loc}");
    println!("{}", serde_json::to_string_pretty(&info)?); Ok(())
}

pub async fn unregister(sk: &SigningKey, du: &str, cb: Option<&str>, ins: bool, v: u8) -> Result<()> {
    let c = client(cb, ins)?; let (dir, k) = kid(&c, sk, du).await?;
    if v >= 2 { eprintln!("[account] POST {} (deactivate)", k); }
    let (info, _, _) = send_signed_request(&c, &k, Some(&json!({"status":"deactivated"})), "deactivate", sk, &Some(k.clone()), &dir).await?;
    println!("{}", serde_json::to_string_pretty(&info)?); Ok(())
}

pub async fn change_key(sk: &SigningKey, du: &str, new_key_path: &str, cb: Option<&str>, ins: bool, v: u8) -> Result<()> {
    let c = client(cb, ins)?; let (dir, k) = kid(&c, sk, du).await?;
    let kc_url = dir.key_change.as_deref().unwrap_or(&k); // Pebble uses /rollover-account-key

    let new_sk = crate::parse_account_key(new_key_path)?;
    let new_jwk = new_sk.jwk();
    let old_jwk = sk.jwk();

    // Inner JWS: signed by NEW key, payload = {account, oldKey}
    let inner_payload = json!({"account": &k, "oldKey": old_jwk});
    let inner_payload_str = serde_json::to_string(&inner_payload)?;
    let inner_protected = json!({"alg": old_jwk["alg"].as_str().unwrap_or("RS256"), "jwk": new_jwk, "url": kc_url});
    let inner_protected64 = b64(serde_json::to_string(&inner_protected)?.as_bytes());
    let inner_payload64 = b64(inner_payload_str.as_bytes());
    let inner_signing_input = format!("{inner_protected64}.{inner_payload64}");
    let inner_sig = b64(&new_sk.sign(inner_signing_input.as_bytes())?);
    let inner_jws = json!({
        "protected": inner_protected64,
        "payload": inner_payload64,
        "signature": inner_sig,
    });
    let inner_jws_str = serde_json::to_string(&inner_jws)?;

    // Outer JWS: signed by OLD key, payload = inner JWS as raw bytes (not JSON-encoded)
    let outer_payload64 = b64(inner_jws_str.as_bytes());
    let nonce = crate::get_nonce(&c, &dir).await?;
    let outer_protected = json!({"alg": old_jwk["alg"].as_str().unwrap_or("RS256"), "kid": &k, "nonce": nonce, "url": kc_url});
    let outer_protected64 = b64(serde_json::to_string(&outer_protected)?.as_bytes());
    let outer_signing_input = format!("{outer_protected64}.{outer_payload64}");
    let outer_sig = b64(&sk.sign(outer_signing_input.as_bytes())?);
    let outer_jws = json!({
        "protected": outer_protected64,
        "payload": outer_payload64,
        "signature": outer_sig,
    });
    if v >= 2 { eprintln!("[account] POST {kc_url} (key-change)"); }
    let resp = c.post(kc_url).header("Content-Type", "application/jose+json")
        .body(serde_json::to_vec(&outer_jws)?).send().await.context("key-change")?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.context("parse response")?;
    if !status.is_success() {
        anyhow::bail!("key-change failed: HTTP {status}\n{}", serde_json::to_string_pretty(&body)?);
    }
    println!("{}", serde_json::to_string_pretty(&body)?); Ok(())
}
