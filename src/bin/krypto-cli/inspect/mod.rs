// SPDX-License-Identifier: MIT OR Apache-2.0
//! `krypto-cli inspect`: what a file or a dump is, and how it was made,
//! without a key (0.8.0). Part 1 is what krypto makes, in this file; part 2 is
//! what others make, in the modules. `docs/Inspect.md` lists what is
//! recognized, and which of it is tested against real files.
//!
//! It tells what something is and which algorithm made it, never what it
//! holds: no key, no plaintext and no hash value is printed. The report keeps
//! only printable ASCII: any other character is removed where the report is
//! written, and the line says how many were (0.8.2).

use krypto::{base64, blob_key_id, hex};

mod der;
mod files;
mod pgp;
mod pkix;
mod ssh;
mod text;

/// What `inspect` found: a name and the facts about it. `changed` is set for a
/// krypto blob whose header names a format version or an algorithm krypto does
/// not know, or whose header is cut short (0.9.0), which is exit 3, as for
/// `open`. `too_deep` is set where the depth limit kept `inspect` from
/// unwrapping further, and the report says so (0.8.2).
pub struct Finding {
    pub what: String,
    pub facts: Vec<(&'static str, String)>,
    pub changed: bool,
    pub too_deep: bool,
}

impl Finding {
    fn new(what: impl Into<String>) -> Self {
        Finding {
            what: what.into(),
            facts: Vec::new(),
            changed: false,
            too_deep: false,
        }
    }

    fn fact(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.facts.push((name, value.into()));
        self
    }

    /// The report: the name, then one fact per line. The name and each value
    /// go through [`visible`] here, so all text reaches the terminal by the
    /// same rule, also text taken from the input (0.8.2).
    pub fn report(&self) -> String {
        let mut out = visible(&self.what);
        for (name, value) in &self.facts {
            out += &format!("\n  {name:<11} {}", visible(value));
        }
        out
    }
}

/// `text` with only printable ASCII (0x20 to 0x7e) kept, so the input cannot
/// drive the terminal or add a line to the report. How many characters were
/// removed is said at the end, as `[3 characters not shown]` (0.8.2).
fn visible(text: &str) -> String {
    let kept: String = text.chars().filter(|c| matches!(c, ' '..='~')).collect();
    let removed = text.chars().count() - kept.chars().count();
    let marker = match removed {
        0 => return kept,
        1 => "[1 character not shown]".to_string(),
        n => format!("[{n} characters not shown]"),
    };
    if kept.is_empty() {
        marker
    } else {
        format!("{kept} {marker}")
    }
}

/// The last line of a report where the depth limit kept `inspect` from
/// unwrapping further (0.8.2).
const TOO_DEEP: &str = "stopped at the limit of two levels of unwrapping";

/// What `input` is.
pub fn inspect(input: &[u8]) -> Finding {
    let found = inspect_at(input, 0);
    if found.too_deep {
        found.fact("note", TOO_DEEP)
    } else {
        found
    }
}

fn inspect_at(input: &[u8], depth: u8) -> Finding {
    // Part 1: what krypto makes.
    let ours = [blob, store, pkcs8_p256, der_ecdsa_signature];
    if let Some(found) = ours.iter().find_map(|f| f(input)) {
        return found;
    }
    // Part 2: what others make, told from bytes.
    let theirs = [files::from_magic, pkix::from_der, pgp::from_binary];
    if let Some(found) = theirs.iter().find_map(|f| f(input)) {
        return found;
    }
    let mut too_deep = false;
    if let Ok(text) = std::str::from_utf8(input) {
        let text = text.trim();
        if let Some(found) = phc_argon2id(text) {
            return found;
        }
        let found = pem(text, depth)
            .or_else(|| ssh::rfc4716(text))
            .or_else(|| ssh::putty(text))
            .or_else(|| ssh::public_line(text))
            .or_else(|| text::from_text(text));
        if let Some(found) = found {
            return found;
        }
        // Hex and base64 are unwrapped once or twice, never more; where the
        // limit stops them, the report says so (0.8.2).
        if depth < 2 {
            if let Some(found) = unwrapped(text, depth, &mut too_deep) {
                return found;
            }
        } else {
            too_deep = looks_wrapped(text);
        }
    }
    let mut found = by_length(input).unwrap_or_else(|| unknown(input));
    found.too_deep = too_deep;
    found
}

/// PEM: `-----BEGIN <label>-----`, base64, `-----END <label>-----`. The label
/// says what to look for; the content is told as DER or by its own format.
/// Content that could hold more wrapping is looked into at most two levels
/// deep, as for hex and base64; deeper, the block is told by its label, and
/// the report says the limit was reached (0.8.2).
fn pem(text: &str, depth: u8) -> Option<Finding> {
    let label = text.strip_prefix("-----BEGIN ")?.split("-----").next()?;
    if label.starts_with("PGP ") {
        return pgp::from_armor(text);
    }
    let body: String = text
        .lines()
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .filter(|l| !l.contains(':'))
        .map(str::trim)
        .collect();
    let bytes = base64::decode(&body).ok();
    let mut too_deep = false;
    let inner = bytes.as_deref().and_then(|b| match label {
        "OPENSSH PRIVATE KEY" => ssh::private_key(b),
        "SSH SIGNATURE" => ssh::signature(b),
        "RSA PUBLIC KEY" => pkix::pkcs1_public(b),
        _ if depth < 2 => {
            let inner = inspect_at(b, depth + 1);
            too_deep = inner.too_deep;
            Some(inner).filter(|f| f.what != NOT_RECOGNIZED)
        }
        _ => {
            too_deep = true;
            None
        }
    });
    let mut found = inner.unwrap_or_else(|| {
        let mut found = Finding::new(pem_label_name(label));
        found.too_deep = too_deep;
        found
    });
    found
        .facts
        .insert(0, ("wrapped in", format!("PEM ({label})")));
    // A legacy encrypted PEM key names its cipher in DEK-Info.
    if let Some(dek) = text.lines().find_map(|l| l.strip_prefix("DEK-Info: ")) {
        let cipher = dek.split(',').next().unwrap_or_default();
        found = found.fact("encrypted", cipher);
    }
    Some(found)
}

/// What a PEM label says the block is, for when its content cannot be read,
/// as with a key encrypted the legacy way.
fn pem_label_name(label: &str) -> String {
    match label {
        "RSA PRIVATE KEY" => "RSA private key (PKCS#1)",
        "EC PRIVATE KEY" => "EC private key (SEC1)",
        "DSA PRIVATE KEY" => "DSA private key",
        "PRIVATE KEY" => "private key (PKCS#8)",
        "ENCRYPTED PRIVATE KEY" => "encrypted private key (PKCS#8)",
        "PUBLIC KEY" => "public key (SubjectPublicKeyInfo)",
        "CERTIFICATE" => "X.509 certificate",
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
            "certificate signing request (PKCS#10)"
        }
        "X509 CRL" => "certificate revocation list (X.509 CRL)",
        "PKCS7" | "CMS" => "CMS / PKCS#7",
        "DH PARAMETERS" => "Diffie-Hellman parameters",
        "EC PARAMETERS" => "EC parameters",
        _ => return format!("PEM block: {label}"),
    }
    .to_string()
}

/// Seconds since 1970 as a UTC date and time.
fn date_time(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
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
    // Starts with `FAFN` but is cut short of the 54-byte header: a changed
    // blob, `Auth` since 0.9.0 — reported as cut short, flagged changed.
    if input.len() < 54 {
        let mut found = found.fact("header", "cut short");
        found.changed = true;
        return Some(found);
    }
    // `blob_key_id` reads the header as `open` does: `Auth` if a field was
    // changed to a value krypto does not know.
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

/// E2: a store file, from `SecretStore`. The version byte at offset 4 picks
/// the header's size: 37 bytes for v1, 109 for v2 (key check, counter and
/// container MAC, spec/SPEC-secretstore.md). A v2 header's counter is shown
/// and its MACs are labeled present but not verified — `inspect` has no key.
fn store(input: &[u8]) -> Option<Finding> {
    const V1_HEADER: usize = 4 + 1 + 16 + 16;
    const V2_HEADER: usize = V1_HEADER + 32 + 8 + 32;
    const NAMES_SHOWN: usize = 20;
    if !input.starts_with(b"FST1") {
        return None;
    }
    let found = Finding::new("krypto store file (krypto::SecretStore)");
    if input.len() < 5 {
        return Some(found.fact("header", "cut short"));
    }
    let ver = input[4];
    let header = match ver {
        1 => V1_HEADER,
        2 => V2_HEADER,
        // A version this krypto does not know: its header's size is not known
        // either, so nothing past the version byte is read.
        _ => {
            return Some(
                found
                    .fact("format", ver.to_string())
                    .fact("header", format!("unsupported store version {ver}")),
            )
        }
    };
    if input.len() < header {
        // A v2 file cut short of its header is a changed file: `Auth` at
        // `SecretStore::open` (spec/SPEC-secretstore.md §4), flagged changed
        // here as a blob cut short of its header is. A v1 header cut short is
        // `Format` there and is not flagged.
        let mut found = found.fact("header", "cut short");
        found.changed = ver == 2;
        return Some(found);
    }
    let mut found = found
        .fact("format", ver.to_string())
        .fact("key id", hex::encode(&input[21..37]));
    if ver == 2 {
        let counter = u64::from_le_bytes(input[69..77].try_into().unwrap());
        found = found
            .fact("counter", counter.to_string())
            .fact("mac", "present, not verified");
    }
    let (names, algs, damaged) = entries_of(input, header);
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

/// The entries of a store file from `at` on, in the encoding v1 and v2 share
/// (`name_len u16LE | name | blob_len u32LE | blob`): the names, the
/// algorithms of the blobs, and where the file is cut short, if it is.
fn entries_of(input: &[u8], mut at: usize) -> (Vec<String>, Vec<&'static str>, Option<usize>) {
    let mut names = Vec::new();
    let mut algs = Vec::new();
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
        names.push(String::from_utf8_lossy(name).into_owned());
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
    (names, algs, damaged)
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
/// base64. Base64 not taken still sets `too_deep` where the depth limit
/// stopped the unwrapping inside it (0.8.2).
fn unwrapped(text: &str, depth: u8, too_deep: &mut bool) -> Option<Finding> {
    if text.len() >= 2 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(&text.to_ascii_lowercase()) {
            return Some(wrapped(inspect_at(&bytes, depth + 1), "hex"));
        }
    }
    if text.len() >= 8 {
        if let Ok(bytes) = base64::decode(text) {
            let inner = inspect_at(&bytes, depth + 1);
            if inner.what != NOT_RECOGNIZED {
                return Some(wrapped(inner, "base64"));
            }
            *too_deep = inner.too_deep;
        }
    }
    None
}

/// Whether [`unwrapped`] would try `text`: hex, or base64 that decodes. Its
/// tests are the same as there (0.8.2).
fn looks_wrapped(text: &str) -> bool {
    let hex = text.len() >= 2
        && text.bytes().all(|b| b.is_ascii_hexdigit())
        && hex::decode(&text.to_ascii_lowercase()).is_ok();
    hex || (text.len() >= 8 && base64::decode(text).is_ok())
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
             a krypto master key or a SHA-256 hash; the length alone cannot tell them apart",
        )),
        64 => Some(Finding::new("64 bytes").fact(
            "could be",
            "an Ed25519 signature or a SHA-512 hash, or other data",
        )),
        65 if input[0] == 0x04 => Some(
            Finding::new("ECDSA P-256 public key (SEC1, uncompressed)")
                .fact("note", "by its length and first byte only"),
        ),
        n => text::hash_by_length(n)
            .map(|hash| Finding::new(format!("{n} bytes")).fact("could be", hash)),
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
