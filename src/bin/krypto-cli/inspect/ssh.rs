// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenSSH: private keys, public keys (one line, and RFC 4716), signatures
//! (`ssh-keygen -Y sign`), and PuTTY keys.

use super::Finding;

/// An SSH wire string: a u32 length and the bytes.
fn string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let s = input.get(4..4 + len)?;
    Some((s, &input[4 + len..]))
}

/// A public key blob: its type, and for RSA the modulus size.
fn key_type(blob: &[u8]) -> Option<String> {
    let (kind, rest) = string(blob)?;
    let kind = std::str::from_utf8(kind).ok()?;
    Some(if kind == "ssh-rsa" {
        let (_e, rest) = string(rest)?;
        let (n, _) = string(rest)?;
        format!("ssh-rsa, RSA {} bits", super::der::integer_bits(n))
    } else {
        kind.to_string()
    })
}

fn fingerprint(blob: &[u8]) -> String {
    format!(
        "SHA256:{}",
        krypto::base64::encode_nopad(&krypto::sha256(blob))
    )
}

const KEY_TYPES: [&str; 9] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-ed448",
];

/// One `authorized_keys` line: `<type> <base64> [comment]`.
pub fn public_line(text: &str) -> Option<Finding> {
    let mut parts = text.split_whitespace();
    let kind = parts.next()?;
    if !KEY_TYPES.contains(&kind) {
        return None;
    }
    let blob = krypto::base64::decode(parts.next()?).ok()?;
    Some(
        Finding::new("OpenSSH public key")
            .fact("algorithm", key_type(&blob)?)
            .fact("fingerprint", fingerprint(&blob)),
    )
}

/// RFC 4716: `---- BEGIN SSH2 PUBLIC KEY ----`, headers, base64, end line.
pub fn rfc4716(text: &str) -> Option<Finding> {
    if !text.starts_with("---- BEGIN SSH2 PUBLIC KEY ----") {
        return None;
    }
    let mut body = String::new();
    let mut continued = false;
    for line in text.lines().skip(1) {
        if line.starts_with("---- END") {
            break;
        }
        if continued || line.contains(':') {
            continued = line.ends_with('\\');
            continue;
        }
        body.push_str(line.trim());
    }
    let blob = krypto::base64::decode(&body).ok()?;
    Some(
        Finding::new("SSH2 public key (RFC 4716)")
            .fact("algorithm", key_type(&blob)?)
            .fact("fingerprint", fingerprint(&blob)),
    )
}

/// `openssh-key-v1`: cipher, KDF, then the public key of each key.
pub fn private_key(body: &[u8]) -> Option<Finding> {
    let rest = body.strip_prefix(b"openssh-key-v1\0")?;
    let (cipher, rest) = string(rest)?;
    let (kdf, rest) = string(rest)?;
    let (_kdf_options, rest) = string(rest)?;
    let count = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    let (public, _) = string(&rest[4..])?;
    let cipher = String::from_utf8_lossy(cipher).into_owned();
    let encrypted = if cipher == "none" {
        "no".to_string()
    } else {
        format!("{cipher}, key from {}", String::from_utf8_lossy(kdf))
    };
    Some(
        Finding::new("OpenSSH private key")
            .fact("algorithm", key_type(public)?)
            .fact("keys", count.to_string())
            .fact("encrypted", encrypted)
            .fact("key", "not shown"),
    )
}

/// `SSHSIG`: version, public key, namespace, reserved, hash, signature.
pub fn signature(body: &[u8]) -> Option<Finding> {
    let rest = body.strip_prefix(b"SSHSIG")?;
    let version = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    let (public, rest) = string(&rest[4..])?;
    let (namespace, rest) = string(rest)?;
    let (_reserved, rest) = string(rest)?;
    let (hash, _) = string(rest)?;
    Some(
        Finding::new("SSH signature (ssh-keygen -Y sign)")
            .fact("version", version.to_string())
            .fact("algorithm", key_type(public)?)
            .fact("hash", String::from_utf8_lossy(hash).into_owned())
            .fact("namespace", super::printable(namespace)),
    )
}

/// PuTTY: `PuTTY-User-Key-File-2: ssh-rsa`, then `Encryption:` and, in
/// version 3, `Key-Derivation:`.
pub fn putty(text: &str) -> Option<Finding> {
    let first = text.lines().next()?;
    let (head, kind) = first.split_once(": ")?;
    let version = head.strip_prefix("PuTTY-User-Key-File-")?;
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
    };
    let mut found = Finding::new("PuTTY private key (.ppk)")
        .fact("version", super::printable(version.as_bytes()))
        .fact("algorithm", super::printable(kind.as_bytes()));
    if let Some(enc) = field("Encryption:") {
        found = found.fact(
            "encrypted",
            if enc == "none" {
                "no".into()
            } else {
                super::printable(enc.as_bytes())
            },
        );
    }
    if let Some(kdf) = field("Key-Derivation:") {
        found = found.fact("key from", super::printable(kdf.as_bytes()));
    }
    Some(found.fact("key", "not shown"))
}
