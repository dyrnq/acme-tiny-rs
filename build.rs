fn main() {
    // Git short hash
    if let Ok(out) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if let Ok(hash) = String::from_utf8(out.stdout) {
            println!("cargo:rustc-env=GIT_HASH={}", hash.trim());
        }
    }

    // Build time (UTC) via system date command (zero extra deps)
    if let Ok(out) = std::process::Command::new("date")
        .args(["+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        if let Ok(ts) = String::from_utf8(out.stdout) {
            println!("cargo:rustc-env=BUILD_TIME={}", ts.trim());
        }
    }
}
