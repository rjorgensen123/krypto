// SPDX-License-Identifier: MIT OR Apache-2.0
//! Formats that are text: tokens, password hashes, hashes and fingerprints,
//! age, minisign and signify, Ansible Vault, SOPS, JSON Web Keys and
//! Sigstore bundles.

use super::{printable, Finding};

/// Any of the formats below.
pub fn from_text(text: &str) -> Option<Finding> {
    password_hash(text)
        .or_else(|| age(text))
        .or_else(|| age_key(text))
        .or_else(|| minisign(text))
        .or_else(|| ansible_vault(text))
        .or_else(|| sops(text))
        .or_else(|| sigstore(text))
        .or_else(|| jwk(text))
        .or_else(|| paseto(text))
        .or_else(|| jose(text))
        .or_else(|| fernet(text))
        .or_else(|| fingerprint(text))
}

/// The string value of `"key"` in a JSON text, found by scanning: enough for
/// headers and keys, not a JSON parser.
pub fn json_string(json: &str, key: &str) -> Option<String> {
    let at = json.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = json[at..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(printable(&rest.as_bytes()[..end]))
}

/// base64url without padding, as in JWT, Fernet and PASETO.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut s: String = text
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    s = s.trim_end_matches('=').to_string();
    krypto::base64::decode_nopad(&s).ok()
}

/// Password hashes by their prefix.
fn password_hash(text: &str) -> Option<Finding> {
    let found = |what: &str| Some(Finding::new(format!("password hash ({what})")));
    if let Some(rest) = text
        .strip_prefix("$argon2i$")
        .or_else(|| text.strip_prefix("$argon2d$"))
    {
        let variant = if text.starts_with("$argon2i$") {
            "Argon2i"
        } else {
            "Argon2d"
        };
        return found(&format!("PHC string, {variant}")).map(|f| {
            f.fact(
                "parameters",
                printable(rest.split('$').nth(1).unwrap_or("").as_bytes()),
            )
        });
    }
    if let Some(rest) = text.strip_prefix("$scrypt$") {
        return found("PHC string, scrypt").map(|f| {
            f.fact(
                "parameters",
                printable(rest.split('$').next().unwrap_or("").as_bytes()),
            )
        });
    }
    if let Some(rest) = text.strip_prefix("$pbkdf2-") {
        let (hash, rest) = rest.split_once('$')?;
        let rounds = rest.split('$').next().unwrap_or("");
        return found(&format!(
            "PBKDF2-{}",
            printable(hash.to_uppercase().as_bytes())
        ))
        .map(|f| f.fact("iterations", printable(rounds.as_bytes())));
    }
    for (prefix, name) in [
        ("$2a$", "bcrypt"),
        ("$2b$", "bcrypt"),
        ("$2y$", "bcrypt"),
        ("$2x$", "bcrypt"),
    ] {
        if let Some(rest) = text.strip_prefix(prefix) {
            let cost = rest.split('$').next().unwrap_or("");
            return found(name).map(|f| f.fact("cost", printable(cost.as_bytes())));
        }
    }
    let crypt = [
        ("$1$", "MD5-crypt, weak"),
        ("$apr1$", "Apache MD5, weak"),
        ("$5$", "SHA-256-crypt"),
        ("$6$", "SHA-512-crypt"),
        ("$y$", "yescrypt"),
        ("$gy$", "gost-yescrypt"),
        ("$7$", "scrypt (crypt)"),
    ];
    if let Some((_, name)) = crypt.iter().find(|(p, _)| text.starts_with(p)) {
        let mut f = Finding::new(format!("password hash ({name})"));
        if let Some(r) = text
            .split('$')
            .nth(2)
            .and_then(|s| s.strip_prefix("rounds="))
        {
            f = f.fact("rounds", printable(r.as_bytes()));
        }
        return Some(f);
    }
    for prefix in [
        "pbkdf2_sha256$",
        "pbkdf2_sha1$",
        "argon2$",
        "bcrypt_sha256$",
        "scrypt$",
    ] {
        if let Some(rest) = text.strip_prefix(prefix) {
            let mut f = Finding::new(format!(
                "password hash (Django, {})",
                prefix.trim_end_matches('$')
            ));
            if prefix.starts_with("pbkdf2") {
                f = f.fact(
                    "iterations",
                    printable(rest.split('$').next().unwrap_or("").as_bytes()),
                );
            }
            return Some(f);
        }
    }
    for (prefix, name) in [
        ("{SSHA512}", "salted SHA-512"),
        ("{SSHA256}", "salted SHA-256"),
        ("{SSHA}", "salted SHA-1"),
        ("{SHA}", "SHA-1, unsalted"),
        ("{SMD5}", "salted MD5"),
        ("{MD5}", "MD5, unsalted"),
        ("{CRYPT}", "crypt"),
    ] {
        if text.starts_with(prefix) {
            return found(&format!("LDAP, {name}"));
        }
    }
    if text.len() == 41 && text.starts_with('*') && text[1..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return found("MySQL, SHA-1 of SHA-1, unsalted");
    }
    None
}

/// age: `age-encryption.org/v1`, then one stanza per recipient.
fn age(text: &str) -> Option<Finding> {
    if !text.starts_with("age-encryption.org/v1") {
        return None;
    }
    let recipients: Vec<String> = text
        .lines()
        .filter_map(|l| l.strip_prefix("-> "))
        .map(|l| printable(l.split_whitespace().next().unwrap_or("").as_bytes()))
        .collect();
    Some(
        Finding::new("age encrypted file")
            .fact(
                "recipients",
                if recipients.is_empty() {
                    "none".into()
                } else {
                    recipients.join(", ")
                },
            )
            .fact(
                "cipher",
                "ChaCha20-Poly1305 (STREAM), file key from the recipients",
            ),
    )
}

fn age_key(text: &str) -> Option<Finding> {
    if text.starts_with("AGE-SECRET-KEY-1")
        || text.lines().any(|l| l.starts_with("AGE-SECRET-KEY-1"))
    {
        return Some(
            Finding::new("age identity")
                .fact("algorithm", "X25519")
                .fact("key", "not shown"),
        );
    }
    if text.starts_with("AGE-PLUGIN-") {
        return Some(Finding::new("age plugin identity").fact("key", "not shown"));
    }
    if text.starts_with("age1") && text.len() >= 62 && !text.contains(char::is_whitespace) {
        return Some(Finding::new("age recipient").fact("algorithm", "X25519 public key"));
    }
    None
}

/// minisign and signify: an `untrusted comment:` line, then base64 that
/// starts with the algorithm.
fn minisign(text: &str) -> Option<Finding> {
    let mut lines = text.lines();
    let comment = lines.next()?.strip_prefix("untrusted comment: ")?;
    let data = krypto::base64::decode(lines.next()?.trim()).ok()?;
    let tool = if comment.contains("signify") {
        "signify"
    } else {
        "minisign"
    };
    let kind = match (data.get(..2), data.len()) {
        (Some(b"Ed"), 42) => "public key",
        (Some(b"Ed" | b"ED"), 74) => "signature",
        (Some(b"Ed"), _) => "secret key",
        _ => return None,
    };
    let algorithm = if data.starts_with(b"ED") {
        "Ed25519 over BLAKE2b-512"
    } else {
        "Ed25519"
    };
    let mut found = Finding::new(format!("{tool} {kind}")).fact("algorithm", algorithm);
    if kind == "secret key" {
        found = found.fact("key", "not shown");
    }
    Some(found)
}

fn ansible_vault(text: &str) -> Option<Finding> {
    let header = text.lines().next()?.strip_prefix("$ANSIBLE_VAULT;")?;
    let mut parts = header.split(';');
    let version = parts.next()?;
    let cipher = parts.next().unwrap_or("");
    Some(
        Finding::new("Ansible Vault")
            .fact("version", printable(version.as_bytes()))
            .fact(
                "cipher",
                if cipher == "AES256" {
                    "AES-256-CTR with HMAC-SHA256, key from PBKDF2-SHA256".to_string()
                } else {
                    printable(cipher.as_bytes())
                },
            ),
    )
}

fn sops(text: &str) -> Option<Finding> {
    if !text.contains("ENC[AES256_GCM,data:") || !text.contains("sops") {
        return None;
    }
    let keys: Vec<&str> = ["age", "pgp", "kms", "gcp_kms", "azure_kv", "hc_vault"]
        .into_iter()
        .filter(|k| text.contains(&format!("\"{k}\"")) || text.contains(&format!("{k}:")))
        .collect();
    let mut found =
        Finding::new("SOPS encrypted file").fact("cipher", "AES-256-GCM for each value");
    if !keys.is_empty() {
        found = found.fact("data key held by", keys.join(", "));
    }
    Some(found)
}

fn sigstore(text: &str) -> Option<Finding> {
    let media = json_string(text, "mediaType")?;
    media
        .starts_with("application/vnd.dev.sigstore.bundle")
        .then(|| Finding::new("Sigstore bundle").fact("media type", media))
}

fn jwk(text: &str) -> Option<Finding> {
    if !text.starts_with('{') || !text.contains("\"kty\"") {
        return None;
    }
    let set = text.contains("\"keys\"");
    let kty = json_string(text, "kty")?;
    let mut found = Finding::new(if set {
        "JSON Web Key Set"
    } else {
        "JSON Web Key"
    })
    .fact("key type", kty);
    if let Some(crv) = json_string(text, "crv") {
        found = found.fact("curve", crv);
    }
    if let Some(alg) = json_string(text, "alg") {
        found = found.fact("algorithm", alg);
    }
    if text.contains("\"d\"") || text.contains("\"k\"") {
        found = found.fact("private", "yes; the key is not shown");
    }
    Some(found)
}

fn paseto(text: &str) -> Option<Finding> {
    let mut parts = text.splitn(3, '.');
    let version = parts.next()?;
    let purpose = parts.next()?;
    let algorithm = match (version, purpose) {
        ("v1", "local") => "AES-256-CTR with HMAC-SHA384",
        ("v1", "public") => "RSA-PSS with SHA-384",
        ("v2", "local") => "XChaCha20-Poly1305",
        ("v2", "public") => "Ed25519",
        ("v3", "local") => "AES-256-CTR with HMAC-SHA384",
        ("v3", "public") => "ECDSA P-384",
        ("v4", "local") => "XChaCha20 with BLAKE2b-MAC",
        ("v4", "public") => "Ed25519",
        _ => return None,
    };
    Some(Finding::new(format!("PASETO {version}.{purpose} token")).fact("algorithm", algorithm))
}

/// JWS/JWT (three parts) and JWE (five parts), compact form.
fn jose(text: &str) -> Option<Finding> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 3 && parts.len() != 5 {
        return None;
    }
    let header = String::from_utf8(base64url(parts[0])?).ok()?;
    let alg = json_string(&header, "alg")?;
    let mut found = if parts.len() == 5 {
        Finding::new("JWE (JSON Web Encryption)")
            .fact("key management", alg)
            .fact(
                "content",
                json_string(&header, "enc").unwrap_or_else(|| "unknown".into()),
            )
    } else if alg == "none" {
        Finding::new("JWT/JWS").fact("algorithm", "none: not signed")
    } else {
        Finding::new("JWT/JWS").fact("algorithm", alg)
    };
    if let Some(kid) = json_string(&header, "kid") {
        found = found.fact("key id", kid);
    }
    Some(found)
}

/// Fernet: base64url of 0x80, a timestamp, an IV, the ciphertext and a MAC.
fn fernet(text: &str) -> Option<Finding> {
    if !text.starts_with("gAAAAA") {
        return None;
    }
    let data = base64url(text)?;
    if data.first() != Some(&0x80) || data.len() < 57 {
        return None;
    }
    let seconds = u64::from_be_bytes(data.get(1..9)?.try_into().ok()?);
    Some(
        Finding::new("Fernet token")
            .fact("algorithm", "AES-128-CBC with HMAC-SHA256")
            .fact("made", super::date_time(seconds)),
    )
}

/// Hashes and fingerprints told by their form.
fn fingerprint(text: &str) -> Option<Finding> {
    if let Some(rest) = text.strip_prefix("SHA256:") {
        if rest.len() == 43 && krypto::base64::decode_nopad(rest).is_ok() {
            return Some(Finding::new("SSH key fingerprint").fact("hash", "SHA-256"));
        }
    }
    let pairs: Vec<&str> = text.trim_start_matches("MD5:").split(':').collect();
    if pairs.len() == 16
        && pairs
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Some(Finding::new("SSH key fingerprint").fact("hash", "MD5 (old form)"));
    }
    let groups: Vec<&str> = text.split_whitespace().collect();
    if groups.len() == 10
        && groups
            .iter()
            .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Some(Finding::new("OpenPGP v4 key fingerprint").fact("hash", "SHA-1"));
    }
    None
}

/// A hash, told only by its length in bytes; a guess.
pub fn hash_by_length(len: usize) -> Option<&'static str> {
    Some(match len {
        16 => "an MD5 or NTLM hash, or a 128-bit key",
        20 => "a SHA-1 or RIPEMD-160 hash",
        28 => "a SHA-224 hash",
        32 => "a SHA-256 hash",
        48 => "a SHA-384 hash",
        64 => "a SHA-512 hash",
        _ => return None,
    })
}
