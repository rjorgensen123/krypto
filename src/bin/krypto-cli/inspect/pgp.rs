// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenPGP (GnuPG): messages, keys and signatures, binary or armored. The
//! packets are walked and their algorithm IDs named (RFC 9580, RFC 4880).

use super::Finding;

/// One packet: its tag and its body. `body` is `None` for a body of partial
/// length, a stream that is not followed further; `head` is the start of the
/// body either way, which is where the algorithms are.
struct Packet<'a> {
    tag: u8,
    body: Option<&'a [u8]>,
    head: &'a [u8],
}

/// All packets in `input`, or `None` if it is not a clean packet sequence.
fn packets(input: &[u8]) -> Option<Vec<Packet<'_>>> {
    let mut out = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (&first, after) = rest.split_first()?;
        if first & 0x80 == 0 {
            return None;
        }
        let (tag, len, after) = if first & 0x40 != 0 {
            let tag = first & 0x3f;
            let (&l1, after) = after.split_first()?;
            match l1 {
                0..=191 => (tag, Some(l1 as usize), after),
                192..=223 => {
                    let (&l2, after) = after.split_first()?;
                    (
                        tag,
                        Some(((l1 as usize - 192) << 8) + l2 as usize + 192),
                        after,
                    )
                }
                255 => {
                    let n = u32::from_be_bytes(after.get(..4)?.try_into().ok()?) as usize;
                    (tag, Some(n), &after[4..])
                }
                _ => (tag, None, after),
            }
        } else {
            let tag = (first >> 2) & 0x0f;
            match first & 3 {
                0 => (tag, Some(*after.first()? as usize), &after[1..]),
                1 => (
                    tag,
                    Some(u16::from_be_bytes(after.get(..2)?.try_into().ok()?) as usize),
                    &after[2..],
                ),
                2 => (
                    tag,
                    Some(u32::from_be_bytes(after.get(..4)?.try_into().ok()?) as usize),
                    &after[4..],
                ),
                _ => (tag, None, after),
            }
        };
        if tag == 0 {
            return None;
        }
        match len {
            Some(len) => {
                let body = after.get(..len)?;
                out.push(Packet {
                    tag,
                    body: Some(body),
                    head: body,
                });
                rest = &after[len..];
            }
            None => {
                // A body without a stated length streams a message's data, so
                // it comes only after a key packet; otherwise random bytes pass
                // for one.
                if !out.iter().any(|p: &Packet| p.tag == 1 || p.tag == 3) {
                    return None;
                }
                out.push(Packet {
                    tag,
                    body: None,
                    head: after,
                });
                break;
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

fn public_key_algorithm(id: u8) -> String {
    match id {
        1..=3 => "RSA",
        16 => "Elgamal",
        17 => "DSA",
        18 => "ECDH",
        19 => "ECDSA",
        22 => "EdDSA (legacy)",
        25 => "X25519",
        26 => "X448",
        27 => "Ed25519",
        28 => "Ed448",
        _ => return format!("algorithm {id}"),
    }
    .to_string()
}

fn symmetric_algorithm(id: u8) -> String {
    match id {
        0 => "none",
        1 => "IDEA",
        2 => "3DES",
        3 => "CAST5",
        4 => "Blowfish",
        7 => "AES-128",
        8 => "AES-192",
        9 => "AES-256",
        10 => "Twofish",
        11 => "Camellia-128",
        12 => "Camellia-192",
        13 => "Camellia-256",
        _ => return format!("cipher {id}"),
    }
    .to_string()
}

fn hash_algorithm(id: u8) -> String {
    match id {
        1 => "MD5",
        2 => "SHA-1",
        3 => "RIPEMD-160",
        8 => "SHA-256",
        9 => "SHA-384",
        10 => "SHA-512",
        11 => "SHA-224",
        12 => "SHA3-256",
        14 => "SHA3-512",
        _ => return format!("hash {id}"),
    }
    .to_string()
}

fn aead_algorithm(id: u8) -> String {
    match id {
        1 => "EAX",
        2 => "OCB",
        3 => "GCM",
        _ => return format!("AEAD {id}"),
    }
    .to_string()
}

fn curve(oid: &[u8]) -> &'static str {
    match oid {
        [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01] => "Ed25519",
        [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01] => "Curve25519",
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => "P-256",
        [0x2b, 0x81, 0x04, 0x00, 0x22] => "P-384",
        [0x2b, 0x81, 0x04, 0x00, 0x23] => "P-521",
        [0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => "brainpoolP256r1",
        _ => "other curve",
    }
}

/// A key's algorithm from a public key packet body (v4 or v6).
fn key_description(body: &[u8]) -> Option<String> {
    let version = *body.first()?;
    let (alg, material) = match version {
        4 => (*body.get(5)?, body.get(6..)?),
        6 => (*body.get(5)?, body.get(10..)?),
        _ => return Some(format!("key version {version}")),
    };
    let name = public_key_algorithm(alg);
    Some(match alg {
        1..=3 => {
            let bits = u16::from_be_bytes(material.get(..2)?.try_into().ok()?);
            format!("{name} {bits} bits")
        }
        18 | 19 | 22 => {
            let len = *material.first()? as usize;
            format!("{name} {}", curve(material.get(1..1 + len)?))
        }
        _ => name,
    })
}

/// Whether the first packet starts with a version OpenPGP defines, or for
/// compressed data an algorithm it defines.
fn known_version(p: &Packet) -> bool {
    let Some(&v) = p.head.first() else {
        return false;
    };
    match p.tag {
        1 => matches!(v, 3 | 6),
        2 => matches!(v, 3..=6),
        3 => matches!(v, 4..=6),
        4 => matches!(v, 3 | 6),
        5 | 6 => matches!(v, 3..=6),
        8 => v <= 3,
        18 => matches!(v, 1 | 2),
        20 => v == 1,
        _ => false,
    }
}

/// Any OpenPGP data, from its binary packets.
pub fn from_binary(input: &[u8]) -> Option<Finding> {
    let packets = packets(input)?;
    let first = packets.first()?;
    if !known_version(first) {
        return None;
    }
    match first.tag {
        1 | 3 | 18 | 20 => message(&packets),
        2 | 4 => signature(&packets),
        5 | 6 => key(&packets),
        8 => Some(Finding::new("OpenPGP compressed data")),
        _ => None,
    }
}

fn message(packets: &[Packet]) -> Option<Finding> {
    let mut recipients = Vec::new();
    let mut passphrases = Vec::new();
    let mut data = None;
    for p in packets {
        let Some(body) = p.body else {
            if p.tag == 18 || p.tag == 20 || p.tag == 9 {
                data = Some(data_packet(p.tag, p.head));
            }
            continue;
        };
        match p.tag {
            1 => {
                let version = *body.first()?;
                let alg = match version {
                    3 => *body.get(9)?,
                    6 => *body.get(1 + 1 + *body.get(1)? as usize)?,
                    _ => continue,
                };
                let who = if version == 3 {
                    format!(" to key {}", krypto::hex::encode(body.get(1..9)?))
                } else {
                    String::new()
                };
                recipients.push(format!("{}{who}", public_key_algorithm(alg)));
            }
            3 => {
                let version = *body.first()?;
                let text = match version {
                    4 => format!(
                        "{}, {}",
                        symmetric_algorithm(*body.get(1)?),
                        s2k(body.get(2..)?)
                    ),
                    5 | 6 => format!(
                        "{} with {}",
                        symmetric_algorithm(*body.get(if version == 6 { 2 } else { 1 })?),
                        aead_algorithm(*body.get(if version == 6 { 3 } else { 2 })?)
                    ),
                    _ => continue,
                };
                passphrases.push(text);
            }
            18 | 20 | 9 => data = Some(data_packet(p.tag, body)),
            _ => {}
        }
    }
    let mut found = Finding::new("OpenPGP encrypted message");
    if !recipients.is_empty() {
        found = found.fact("recipients", recipients.join(", "));
    }
    if !passphrases.is_empty() {
        found = found.fact("passphrase", passphrases.join(", "));
    }
    if let Some(data) = data {
        found = found.fact("data", data);
    }
    Some(found)
}

fn data_packet(tag: u8, head: &[u8]) -> String {
    match (tag, head) {
        (18, [2, sym, aead, ..]) => format!(
            "{} with {} (SEIPD v2)",
            symmetric_algorithm(*sym),
            aead_algorithm(*aead)
        ),
        (18, _) => "integrity protected with an MDC (SEIPD v1); the cipher is in the session key"
            .to_string(),
        (20, [1, sym, aead, ..]) => format!(
            "{} with {} (AEAD packet, a GnuPG extension)",
            symmetric_algorithm(*sym),
            aead_algorithm(*aead)
        ),
        (20, _) => "AEAD encrypted (a GnuPG extension)".to_string(),
        _ => "not integrity protected (old SED packet)".to_string(),
    }
}

/// A string-to-key specifier: how a passphrase becomes a key.
fn s2k(spec: &[u8]) -> String {
    match spec {
        [0, hash, ..] => format!(
            "key from the passphrase with {} (simple)",
            hash_algorithm(*hash)
        ),
        [1, hash, ..] => format!(
            "key from the passphrase with salted {}",
            hash_algorithm(*hash)
        ),
        [3, hash, .., count] if spec.len() >= 11 => {
            let c = *count as u32;
            let n = (16 + (c & 15)) << ((c >> 4) + 6);
            format!(
                "key from the passphrase with iterated and salted {}, {n} bytes",
                hash_algorithm(*hash)
            )
        }
        [4, ..] => "key from the passphrase with Argon2".to_string(),
        _ => "key from the passphrase".to_string(),
    }
}

fn signature(packets: &[Packet]) -> Option<Finding> {
    let body = packets.iter().find(|p| p.tag == 2)?.body?;
    let (alg, hash) = match *body.first()? {
        3 => (*body.get(15)?, *body.get(16)?),
        4 | 6 => (*body.get(2)?, *body.get(3)?),
        v => return Some(Finding::new("OpenPGP signature").fact("version", v.to_string())),
    };
    Some(
        Finding::new("OpenPGP signature")
            .fact("algorithm", public_key_algorithm(alg))
            .fact("hash", hash_algorithm(hash)),
    )
}

fn key(packets: &[Packet]) -> Option<Finding> {
    let first = packets.first()?;
    let secret = first.tag == 5;
    let primary = key_description(first.body?)?;
    let subkeys: Vec<String> = packets
        .iter()
        .filter(|p| p.tag == 14 || p.tag == 7)
        .filter_map(|p| key_description(p.body?))
        .collect();
    let user_ids = packets.iter().filter(|p| p.tag == 13).count();
    let mut found = Finding::new(if secret {
        "OpenPGP private key"
    } else {
        "OpenPGP public key"
    })
    .fact("primary key", primary);
    if !subkeys.is_empty() {
        found = found.fact("subkeys", subkeys.join(", "));
    }
    found = found.fact("user ids", user_ids.to_string());
    if secret {
        found = found.fact("key", "not shown");
    }
    Some(found)
}

/// Armored OpenPGP: the label, then the packets in the base64 body.
pub fn from_armor(text: &str) -> Option<Finding> {
    let label = text
        .strip_prefix("-----BEGIN PGP ")?
        .split("-----")
        .next()?;
    let body: String = text
        .lines()
        .skip(1)
        .skip_while(|l| !l.trim().is_empty())
        .take_while(|l| !l.starts_with('=') && !l.starts_with("-----END"))
        .collect::<Vec<_>>()
        .concat();
    let inner = krypto::base64::decode(body.trim())
        .ok()
        .and_then(|b| from_binary(&b));
    let mut found =
        inner.unwrap_or_else(|| Finding::new(format!("OpenPGP {}", label.to_lowercase())));
    found
        .facts
        .insert(0, ("wrapped in", format!("ASCII armor (PGP {label})")));
    Some(found)
}
