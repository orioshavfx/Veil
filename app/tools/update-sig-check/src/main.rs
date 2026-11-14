//! Release gate for in-app updates: fails unless the public key compiled into the app
//! (`UPDATER_PUBKEY` in app/src-tauri/src/updater.rs) is set and the update package's
//! signature verifies with it, for the version being released.
//!
//! It checks the way tauri-plugin-updater 2.14 does before an installed Veil accepts an update
//! (`verify_signature` in its updater.rs, with `requireSignedVersion`): the key and the
//! signature are base64 of minisign text, the minisign signature (and so its trusted comment)
//! must verify, and the trusted comment's `version:` field must be the released version.
//!
//! ```text
//! update-sig-check --source app/src-tauri/src/updater.rs --key-only
//! update-sig-check --source app/src-tauri/src/updater.rs \
//!     --file dist/Veil.app.tar.gz --sig dist/Veil.app.tar.gz.sig --version 1.0.0-beta.2
//! ```
//! `--pubkey <base64>` checks against that key instead of the source (for tests).

use std::process::ExitCode;

use base64::Engine;
use minisign_verify::{PublicKey, Signature};

const KEY_CONST: &str = "pub const UPDATER_PUBKEY: &str =";

/// The value of `UPDATER_PUBKEY` in the Rust source: one line, a plain string literal.
fn key_from_source(source: &str) -> Result<String, String> {
    let lines: Vec<&str> = source.lines().map(str::trim).filter(|l| l.starts_with(KEY_CONST)).collect();
    let line = match lines.as_slice() {
        [one] => *one,
        [] => return Err(format!("no `{KEY_CONST} \"...\";` line found")),
        _ => return Err("UPDATER_PUBKEY is defined more than once".into()),
    };
    let literal = line[KEY_CONST.len()..].trim();
    let value = literal
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix("\";"))
        .filter(|v| !v.contains(['"', '\\']))
        .ok_or_else(|| format!("UPDATER_PUBKEY is not a one-line plain string literal: {literal}"))?;
    Ok(value.trim().to_string())
}

fn b64_text(what: &str, b64: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("{what} is not base64: {e}"))?;
    String::from_utf8(bytes).map_err(|_| format!("{what} is not base64 of text"))
}

/// The key as the plugin reads it: base64 of the minisign public key file.
fn decode_key(pubkey_b64: &str) -> Result<PublicKey, String> {
    if pubkey_b64.trim().is_empty() {
        return Err("UPDATER_PUBKEY is empty: this build could not check any update. Put the contents of \
                    update.key.pub (app/tools/gen-update-key.sh) into app/src-tauri/src/updater.rs"
            .into());
    }
    let text = b64_text("UPDATER_PUBKEY", pubkey_b64)?;
    PublicKey::decode(&text).map_err(|e| format!("UPDATER_PUBKEY is not a minisign public key: {e}"))
}

/// The version recorded by `tauri signer sign --app-version` in the trusted comment.
fn signed_version(trusted_comment: &str) -> Option<&str> {
    trusted_comment.split('\t').find_map(|f| f.strip_prefix("version:"))
}

fn verify(pubkey_b64: &str, data: &[u8], sig_file: &str, version: &str) -> Result<(), String> {
    let key = decode_key(pubkey_b64)?;
    let text = b64_text("the signature file", sig_file)?;
    let sig = Signature::decode(&text).map_err(|e| format!("the signature file is not a minisign signature: {e}"))?;
    // `true` as in the plugin (signatures without a prehash are accepted); the key id must match.
    key.verify(data, &sig, true)
        .map_err(|e| format!("the signature does not verify with UPDATER_PUBKEY: {e}"))?;
    // The trusted comment is covered by the signature that was just checked.
    let want = version.trim_start_matches('v');
    match signed_version(sig.trusted_comment()) {
        None => Err("the signature carries no version (sign with --app-version); the app requires one".into()),
        Some(v) if v.trim_start_matches('v') == want => Ok(()),
        Some(v) => Err(format!("the signature is for version {v}, not {want}")),
    }
}

struct Args {
    source: Option<String>,
    pubkey: Option<String>,
    file: Option<String>,
    sig: Option<String>,
    version: Option<String>,
    key_only: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args { source: None, pubkey: None, file: None, sig: None, version: None, key_only: false };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--source" => a.source = Some(value()?),
            "--pubkey" => a.pubkey = Some(value()?),
            "--file" => a.file = Some(value()?),
            "--sig" => a.sig = Some(value()?),
            "--version" => a.version = Some(value()?),
            "--key-only" => a.key_only = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(a)
}

fn run() -> Result<String, String> {
    let a = parse_args()?;
    let pubkey = match (&a.source, &a.pubkey) {
        (Some(path), None) => {
            let src = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            key_from_source(&src).map_err(|e| format!("{path}: {e}"))?
        }
        (None, Some(k)) => k.clone(),
        _ => return Err("give exactly one of --source <updater.rs> and --pubkey <base64>".into()),
    };
    if a.key_only {
        decode_key(&pubkey)?;
        return Ok("UPDATER_PUBKEY is set and is a minisign public key".into());
    }
    let (Some(file), Some(sig), Some(version)) = (&a.file, &a.sig, &a.version) else {
        return Err("--file, --sig and --version are needed (or --key-only)".into());
    };
    let data = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let sig_text = std::fs::read_to_string(sig).map_err(|e| format!("{sig}: {e}"))?;
    verify(&pubkey, &data, &sig_text, version)?;
    Ok(format!("{file}: signature OK (UPDATER_PUBKEY, version {version})"))
}

fn main() -> ExitCode {
    match run() {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("update-sig-check: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway key pair made with `cargo tauri signer generate` (tauri-cli 2.12.4); its private
    // key was deleted. SIG is `cargo tauri signer sign --app-version 1.2.3` of PAYLOAD.
    const PAYLOAD: &[u8] = b"veil update-sig-check test payload\n";
    const KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEU2MjJBRDJEMzNDNjQ4RTUKUldUbFNNWXpMYTBpNW5MU3RDRnVZd3dRVEYvOUJiemhMRzBOZDNBWHcyLzZGOENhRUE1dUxnV1YK";
    const SIG: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVUbFNNWXpMYTBpNXYvNkthUy8yVVpJY2FqTkhBOUQzbWE1L2QrZXY3ZXY5c01BWnFMZ3hXdnRJMkdWeStnUlcydlhXQUhuWXY2MUo4ZXVvdHp4ZUN0ZGxHOFBKb3pQMUFnPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk0NjkyNjk1CWZpbGU6cGF5bG9hZAl2ZXJzaW9uOjEuMi4zCm9GUWZpQnRlTVg0RHBHVEl5REVOMGtlSzBDSkQ3NDBWVHlNTkFFQVhQRmtBMGtwYnYwWFFTaDg5QmJVbHgwYzQ5bGhzemdjQVhManloYXV2RGp1eUR3PT0K";
    // Another throwaway key (private key deleted as well).
    const OTHER_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDNGRDVERTZBQjc1NjdEQkYKUldTL2ZWYTNhdDdWUHhRV1h4U3FNRzBvcHBuNHQ4U3pDWFNDWi9KRFl6LzZjb2FTZjZ5elprSWMK";

    #[test]
    fn the_right_key_verifies() {
        verify(KEY, PAYLOAD, SIG, "1.2.3").unwrap();
        verify(KEY, PAYLOAD, SIG, "v1.2.3").unwrap();
    }

    #[test]
    fn a_foreign_or_empty_key_fails() {
        assert!(verify(OTHER_KEY, PAYLOAD, SIG, "1.2.3").unwrap_err().contains("does not verify"));
        assert!(verify("", PAYLOAD, SIG, "1.2.3").unwrap_err().contains("empty"));
        assert!(verify("  ", PAYLOAD, SIG, "1.2.3").unwrap_err().contains("empty"));
        assert!(verify("bm90IGEga2V5", PAYLOAD, SIG, "1.2.3").is_err());
    }

    #[test]
    fn other_data_or_version_fails() {
        assert!(verify(KEY, b"something else", SIG, "1.2.3").unwrap_err().contains("does not verify"));
        assert!(verify(KEY, PAYLOAD, SIG, "1.2.4").unwrap_err().contains("not 1.2.4"));
    }

    #[test]
    fn key_is_read_from_the_source() {
        let src = "/// doc\npub const UPDATER_PUBKEY: &str = \"abc=\";\npub const X: &str = \"\";\n";
        assert_eq!(key_from_source(src).unwrap(), "abc=");
        assert_eq!(key_from_source("    pub const UPDATER_PUBKEY: &str = \"\";").unwrap(), "");
        assert!(key_from_source("const OTHER: &str = \"a\";").is_err());
        assert!(key_from_source("pub const UPDATER_PUBKEY: &str = concat!(\"a\");").is_err());
        let twice = "pub const UPDATER_PUBKEY: &str = \"a\";\npub const UPDATER_PUBKEY: &str = \"b\";";
        assert!(key_from_source(twice).is_err());
    }

    #[test]
    fn the_app_source_has_the_expected_shape() {
        let src = include_str!("../../../src-tauri/src/updater.rs");
        key_from_source(src).expect("app/src-tauri/src/updater.rs: UPDATER_PUBKEY must stay a one-line literal");
    }
}
