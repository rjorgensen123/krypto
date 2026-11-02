// SPDX-License-Identifier: MIT OR Apache-2.0
//! Files told by their magic bytes: key collections, encrypted files and
//! disks, and compressed archives, which are not encrypted at all.

use super::Finding;

/// Any of the formats below.
pub fn from_magic(input: &[u8]) -> Option<Finding> {
    let starts = |magic: &[u8]| input.starts_with(magic);
    if starts(&[0xfe, 0xed, 0xfe, 0xed]) {
        return Some(java_keystore(
            input,
            "Java keystore (JKS)",
            "integrity with a SHA-1 keyed digest",
        ));
    }
    if starts(&[0xce, 0xce, 0xce, 0xce]) {
        return Some(java_keystore(
            input,
            "Java keystore (JCEKS)",
            "keys protected with PBE and 3DES",
        ));
    }
    if starts(&[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]) {
        return Some(keepass(input));
    }
    if starts(b"kych") {
        return Some(Finding::new("macOS keychain"));
    }
    if starts(b"LUKS\xba\xbe") {
        return Some(luks(input));
    }
    if input.get(3..11) == Some(b"-FVE-FS-") {
        return Some(Finding::new("BitLocker volume").fact(
            "cipher",
            "AES (CBC or XTS); the details are in its metadata",
        ));
    }
    if starts(b"Salted__") {
        return Some(Finding::new("OpenSSL enc file (salted)").fact(
            "cipher",
            "not recorded in the file: it is whatever was given to openssl enc",
        ));
    }
    if starts(b"\0GITCRYPT\0") {
        return Some(
            Finding::new("git-crypt encrypted file")
                .fact("cipher", "AES-256-CTR, with an HMAC-SHA1 nonce"),
        );
    }
    if starts(b"\0GITCRYPTKEY") {
        return Some(Finding::new("git-crypt key file").fact("key", "not shown"));
    }
    if starts(b"AES") && input.get(3).is_some_and(|&v| v <= 3) && input.len() > 5 {
        return Some(
            Finding::new("AES Crypt file")
                .fact("version", input[3].to_string())
                .fact("cipher", "AES-256-CBC with HMAC-SHA256"),
        );
    }
    if starts(b"PK\x03\x04") {
        return Some(zip(input));
    }
    if starts(b"7z\xbc\xaf\x27\x1c") {
        return Some(Finding::new("7-Zip archive").fact(
            "encryption",
            "if any, AES-256 with a SHA-256 key derivation",
        ));
    }
    if starts(&[0x1f, 0x8b]) {
        return Some(compressed("gzip"));
    }
    if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(compressed("zstd"));
    }
    if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(compressed("xz"));
    }
    if starts(b"BZh") && input.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        return Some(compressed("bzip2"));
    }
    if input.get(257..262) == Some(b"ustar") {
        return Some(Finding::new("tar archive").fact("encrypted", "no"));
    }
    None
}

fn compressed(what: &str) -> Finding {
    Finding::new(format!("{what} compressed data")).fact("encrypted", "no")
}

fn java_keystore(input: &[u8], what: &str, protection: &str) -> Finding {
    let u32_at = |at: usize| {
        input
            .get(at..at + 4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
    };
    let mut found = Finding::new(what);
    if let (Some(version), Some(entries)) = (u32_at(4), u32_at(8)) {
        found = found
            .fact("version", version.to_string())
            .fact("entries", entries.to_string());
    }
    found.fact("protection", protection)
}

/// KeePass KDBX: the version, then header fields; the cipher is field 2 and
/// the key derivation field 11 (KDBX 4) or 6 (KDBX 3, AES-KDF).
fn keepass(input: &[u8]) -> Finding {
    let minor = input.get(8..10).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let major = input.get(10..12).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let mut found = Finding::new("KeePass database (KDBX)");
    if let (Some(major), Some(minor)) = (major, minor) {
        found = found.fact("version", format!("{major}.{minor}"));
    }
    let wide = major.is_some_and(|m| m >= 4);
    let mut at = 12;
    let mut cipher = None;
    let mut kdf = None;
    while let Some(&id) = input.get(at) {
        let (len, data_at) = if wide {
            (
                input
                    .get(at + 1..at + 5)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize),
                at + 5,
            )
        } else {
            (
                input
                    .get(at + 1..at + 3)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize),
                at + 3,
            )
        };
        let Some(data) = len.and_then(|len| input.get(data_at..data_at + len)) else {
            break;
        };
        match id {
            0 => break,
            2 => {
                cipher = Some(match data {
                    [0x31, 0xc1, 0xf2, 0xe6, ..] => "AES-256-CBC",
                    [0xd6, 0x03, 0x8a, 0x2b, ..] => "ChaCha20",
                    [0xad, 0x68, 0xf2, 0x9f, ..] => "Twofish",
                    _ => "unknown",
                })
            }
            11 => {
                let has = |uuid: &[u8]| data.windows(uuid.len()).any(|w| w == uuid);
                kdf = Some(if has(&[0xc9, 0xd9, 0xf3, 0x9a]) {
                    "AES-KDF"
                } else if has(&[0xef, 0x63, 0x6d, 0xdf]) {
                    "Argon2d"
                } else if has(&[0x9e, 0x29, 0x8b, 0x19]) {
                    "Argon2id"
                } else {
                    "unknown"
                })
            }
            6 if !wide => kdf = Some("AES-KDF"),
            _ => {}
        }
        at = data_at + data.len();
    }
    if let Some(cipher) = cipher {
        found = found.fact("cipher", cipher);
    }
    if let Some(kdf) = kdf {
        found = found.fact("key from", kdf);
    }
    found
}

/// LUKS: version 1 names its cipher in the header; version 2 in its JSON area.
fn luks(input: &[u8]) -> Finding {
    let version = input.get(6..8).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let mut found = Finding::new("LUKS encrypted disk");
    let field = |r: std::ops::Range<usize>| {
        input
            .get(r)
            .map(|b| super::printable(b.split(|&c| c == 0).next().unwrap_or_default()))
    };
    match version {
        Some(1) => {
            found = found.fact("version", "1");
            if let (Some(name), Some(mode)) = (field(8..40), field(40..72)) {
                found = found.fact("cipher", format!("{name}-{mode}"));
            }
            if let Some(hash) = field(72..104) {
                found = found.fact("hash", hash);
            }
        }
        Some(2) => {
            found = found.fact("version", "2");
            let json = input
                .get(4096..input.len().min(4096 + 12288))
                .unwrap_or_default();
            let json = String::from_utf8_lossy(json);
            if let Some(enc) = super::text::json_string(&json, "encryption") {
                found = found.fact("cipher", enc);
            }
            if let Some(kdf) = json
                .find("\"kdf\"")
                .and_then(|at| super::text::json_string(&json[at..], "type"))
            {
                found = found.fact("key from", kdf);
            }
        }
        _ => {}
    }
    found
}

/// A zip file: whether its first entry is encrypted, and how.
fn zip(input: &[u8]) -> Finding {
    let flags = input
        .get(6..8)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    let method = input
        .get(8..10)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    let found = Finding::new("zip archive");
    if flags & 1 == 0 {
        return found.fact("encrypted", "no");
    }
    if method == 99 {
        // The AES extra field (0x9901) holds the strength: 1, 2 or 3.
        let name_len = input
            .get(26..28)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
            .unwrap_or(0);
        let extra_len = input
            .get(28..30)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
            .unwrap_or(0);
        let extra = input
            .get(30 + name_len..30 + name_len + extra_len)
            .unwrap_or_default();
        let strength = extra
            .windows(2)
            .position(|w| w == [0x01, 0x99])
            .and_then(|at| extra.get(at + 8));
        let cipher = match strength {
            Some(1) => "AES-128 (WinZip AE)",
            Some(2) => "AES-192 (WinZip AE)",
            Some(3) => "AES-256 (WinZip AE)",
            _ => "AES (WinZip AE)",
        };
        return found.fact("encrypted", cipher);
    }
    found.fact("encrypted", "ZipCrypto (traditional PKWARE, weak)")
}
