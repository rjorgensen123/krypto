// SPDX-License-Identifier: MIT OR Apache-2.0
//! `krypto-cli inspect`: what a file or a dump is, and how it was made,
//! without a key (0.8.0). This is part 1: what krypto makes. `docs/Inspect.md`
//! lists what is recognized.
//!
//! It tells what something is and which algorithm made it, never what it
//! holds: no key, no plaintext and no hash value is printed. The only text
//! taken from the input is the names in a store file, which are not secret,
//! with anything that is not printable ASCII replaced.

use krypto::{base64, blob_key_id, hex};

/// What `inspect` found: a name and the facts about it. `changed` is set for a
/// krypto blob whose header was changed, which is exit 3, as for `open`.
pub struct Finding {
    pub what: String,
    pub facts: Vec<(&'static str, String)>,
    pub changed: bool,
}

impl Finding {
    fn new(what: impl Into<String>) -> Self {
        Finding {
            what: what.into(),
            facts: Vec::new(),
            changed: false,
        }
    }

    fn fact(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.facts.push((name, value.into()));
        self
    }

    /// The report: the name, then one fact per line.
    pub fn report(&self) -> String {
        let mut out = self.what.clone();
        for (name, value) in &self.facts {
            out += &format!("\n  {name:<11} {value}");
        }
        out
    }
}

/// What `input` is.
pub fn inspect(input: &[u8]) -> Finding {
    inspect_at(input, 0)
}

fn inspect_at(input: &[u8], depth: u8) -> Finding {
    let binary = [blob, store, pkcs8_p256, der_ecdsa_signature];
    if let Some(found) = binary.iter().find_map(|f| f(input)) {
        return found;
    }
    if let Ok(text) = std::str::from_utf8(input) {
        let text = text.trim();
        if let Some(found) = phc_argon2id(text) {
            return found;
        }
        // Hex and base64 are unwrapped once or twice, never more.
        if depth < 2 {
            if let Some(found) = unwrapped(text, depth) {
                return found;
            }
        }
    }
    by_length(input).unwrap_or_else(|| unknown(input))
}

fn alg_name(id: u8) -> &'static str {
    match id {
        1 => "AEGIS-256",
        2 => "XChaCha20-Poly1305",
        3 => "AES-256-GCM",
        _ => "unknown to this krypto",
    }
}

/// E1: a krypto blob, from `seal`.
fn blob(input: &[u8]) -> Option<Finding> {
    if !input.starts_with(b"FAFN") {
        return None;
    }
    let found = Finding::new("krypto blob (krypto::seal)");
    // `blob_key_id` reads the header as `open` does: `Auth` if a field was
    // changed to a value krypto does not know, `Format` if it is cut short.
    Some(match blob_key_id(input) {
        Ok(id) => found
            .fact("format", input[4].to_string())
            .fact("algorithm", alg_name(input[5]))
            .fact("key id", hex::encode(&id))
            .fact("bytes", input.len().to_string()),
        Err(krypto::Error::Auth) => {
            let mut found = found.fact(
                "header",
                "changed: a format or an algorithm this krypto does not know",
            );
            found.changed = true;
            found
        }
        Err(_) => found.fact("header", "cut short"),
    })
}

/// E2: a store file, from `SecretStore`.
fn store(input: &[u8]) -> Option<Finding> {
    const HEADER: usize = 4 + 1 + 16 + 16;
    const NAMES_SHOWN: usize = 20;
    if !input.starts_with(b"FST1") {
        return None;
    }
    let found = Finding::new("krypto store file (krypto::SecretStore)");
    if input.len() < HEADER {
        return Some(found.fact("header", "cut short"));
    }
    let mut found = found
        .fact("format", input[4].to_string())
        .fact("key id", hex::encode(&input[21..37]));
    let (mut names, mut algs, mut at) = (Vec::new(), Vec::new(), HEADER);
    let mut damaged = None;
    while at < input.len() {
        let entry = (|| {
            let name_len = u16::from_le_bytes(input.get(at..at + 2)?.try_into().ok()?) as usize;
            let name = input.get(at + 2..at + 2 + name_len)?;
            let len_at = at + 2 + name_len;
            let blob_len = u32::from_le_bytes(input.get(len_at..len_at + 4)?.try_into().ok()?);
            let blob = input.get(len_at + 4..len_at + 4 + blob_len as usize)?;
            Some((name, blob, len_at + 4 + blob_len as usize))
        })();
        let Some((name, blob, next)) = entry else {
            damaged = Some(at);
            break;
        };
        names.push(printable(name));
        let alg = if blob.starts_with(b"FAFN") && blob.len() > 5 {
            alg_name(blob[5])
        } else {
            "not a krypto blob"
        };
        if !algs.contains(&alg) {
            algs.push(alg);
        }
        at = next;
    }
    found = found.fact("entries", names.len().to_string());
    if !names.is_empty() {
        let mut shown = names[..names.len().min(NAMES_SHOWN)].join(", ");
        if names.len() > NAMES_SHOWN {
            shown += &format!(", and {} more", names.len() - NAMES_SHOWN);
        }
        found = found
            .fact("names", shown)
            .fact("algorithm", algs.join(", "));
    }
    if let Some(at) = damaged {
        found = found.fact("damaged", format!("at byte {at}"));
    }
    Some(found)
}

/// Printable ASCII as it is; anything else as `?`, so the input cannot drive
/// the terminal.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// E4: a P-256 private key as krypto writes it, PKCS#8 DER.
fn pkcs8_p256(input: &[u8]) -> Option<Finding> {
    let head = &input[..input.len().min(48)];
    let has = |oid: &[u8]| head.windows(oid.len()).any(|w| w == oid);
    // SEQUENCE, then the version INTEGER 0, then the two OIDs.
    let pkcs8 = input.len() < 512 && input.first() == Some(&0x30) && has(&[0x02, 0x01, 0x00]);
    (pkcs8 && has(OID_EC_PUBLIC_KEY) && has(OID_P256))
        .then(|| Finding::new("ECDSA P-256 private key (PKCS#8, DER)").fact("key", "not shown"))
}

/// E6: an ECDSA signature, DER: SEQUENCE { INTEGER r, INTEGER s }.
fn der_ecdsa_signature(input: &[u8]) -> Option<Finding> {
    let [0x30, len, 0x02, r_len, rest @ ..] = input else {
        return None;
    };
    let (len, r_len) = (*len as usize, *r_len as usize);
    let s_at = r_len;
    let (0x02, s_len) = (*rest.get(s_at)?, *rest.get(s_at + 1)? as usize) else {
        return None;
    };
    let fits = input.len() == 2 + len && len == 4 + r_len + s_len && r_len <= 33 && s_len <= 33;
    fits.then(|| {
        Finding::new("ECDSA signature (DER)").fact("curve", "P-256: r and s fit in 32 bytes")
    })
}

/// E3: a password hash as krypto's `password::hash` writes it.
fn phc_argon2id(text: &str) -> Option<Finding> {
    let rest = text.strip_prefix("$argon2id$")?;
    let mut parts = rest.split('$');
    let version = parts.next()?.strip_prefix("v=")?.to_string();
    let mut m = None;
    let mut t = None;
    let mut p = None;
    for kv in parts.next()?.split(',') {
        match kv.split_once('=')? {
            ("m", v) => m = v.parse::<u32>().ok(),
            ("t", v) => t = v.parse::<u32>().ok(),
            ("p", v) => p = v.parse::<u32>().ok(),
            _ => {}
        }
    }
    let (m, t, p) = (m?, t?, p?);
    let preset = match (m, t, p) {
        (65_536, 3, 2) => "interactive",
        (131_072, 3, 3) => "balanced",
        (262_144, 4, 4) => "high",
        _ => "none of krypto's presets",
    };
    Some(
        Finding::new("password hash (PHC string, Argon2id)")
            .fact("version", version)
            .fact("memory", format!("{} MiB (m={m})", m / 1024))
            .fact("iterations", t.to_string())
            .fact("lanes", p.to_string())
            .fact("preset", preset),
    )
}

/// E8: hex or base64 as krypto writes them, unwrapped. Hex is taken as hex;
/// base64 only when what it holds is recognized, since many words are valid
/// base64.
fn unwrapped(text: &str, depth: u8) -> Option<Finding> {
    if text.len() >= 2 {
        if let Ok(bytes) = hex::decode(text) {
            return Some(wrapped(inspect_at(&bytes, depth + 1), "hex"));
        }
    }
    if text.len() >= 8 {
        if let Ok(bytes) = base64::decode(text) {
            let inner = inspect_at(&bytes, depth + 1);
            if inner.what != NOT_RECOGNIZED {
                return Some(wrapped(inner, "base64"));
            }
        }
    }
    None
}

fn wrapped(mut inner: Finding, how: &str) -> Finding {
    inner.facts.insert(0, ("wrapped in", how.to_string()));
    inner
}

/// E5, E6, E7: what krypto makes that only its length tells.
fn by_length(input: &[u8]) -> Option<Finding> {
    match input.len() {
        32 => Some(Finding::new("32 bytes").fact(
            "could be",
            "an Ed25519 or X25519 public key, an Ed25519 seed, an X25519 private key, \
             or a krypto master key; the length alone cannot tell them apart",
        )),
        64 => {
            Some(Finding::new("64 bytes").fact("could be", "an Ed25519 signature, or other data"))
        }
        65 if input[0] == 0x04 => Some(
            Finding::new("ECDSA P-256 public key (SEC1, uncompressed)")
                .fact("note", "by its length and first byte only"),
        ),
        _ => None,
    }
}

const NOT_RECOGNIZED: &str = "not recognized";

fn unknown(input: &[u8]) -> Finding {
    let kind = if std::str::from_utf8(input).is_ok() {
        "text"
    } else if input.len() >= 256 && entropy(input) > 7.5 {
        "binary that looks random: encrypted, compressed or key material"
    } else {
        "binary"
    };
    Finding::new(NOT_RECOGNIZED)
        .fact("bytes", input.len().to_string())
        .fact("looks like", kind)
}

/// Shannon entropy in bits per byte: near 8 for random data.
fn entropy(input: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in input {
        counts[b as usize] += 1;
    }
    let n = input.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}
