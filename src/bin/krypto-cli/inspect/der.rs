// SPDX-License-Identifier: MIT OR Apache-2.0
//! Just enough DER to tell what an X.509 or PKCS structure is and which
//! algorithms it names. It reads tags, lengths and OIDs; it validates nothing.

/// One DER element: its tag, its content, and what follows it.
#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub body: &'a [u8],
}

/// Read one element from the front of `input`: the element and the rest.
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((
        Tlv {
            tag,
            body: &rest[..len],
        },
        &rest[len..],
    ))
}

/// The whole of `input` as exactly one element, nothing left over.
pub fn whole(input: &[u8]) -> Option<Tlv<'_>> {
    let (tlv, rest) = read(input)?;
    rest.is_empty().then_some(tlv)
}

/// The elements inside a constructed element, in order.
pub fn children(body: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (tlv, next) = read(rest)?;
        out.push(tlv);
        rest = next;
    }
    Some(out)
}

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;

/// An OID's content as dotted text.
pub fn oid_text(body: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut value = 0u64;
    for (i, &b) in body.iter().enumerate() {
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = if i == 0 && value < 80 { value / 40 } else { 2 };
                parts.push(first);
                parts.push(value - first * 40);
            } else {
                parts.push(value);
            }
            value = 0;
        }
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The name of an OID, where it is one we know.
pub fn oid_name(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.5" => "RSA with SHA-1",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.113549.1.1.11" => "RSA with SHA-256",
        "1.2.840.113549.1.1.12" => "RSA with SHA-384",
        "1.2.840.113549.1.1.13" => "RSA with SHA-512",
        "1.2.840.113549.1.1.7" => "RSA-OAEP",
        "1.2.840.10040.4.1" => "DSA",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.132.0.10" => "secp256k1",
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "1.2.840.10045.4.1" => "ECDSA with SHA-1",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "1.3.101.110" => "X25519",
        "1.3.101.111" => "X448",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "1.2.840.113549.1.5.13" => "PBES2",
        "1.2.840.113549.1.5.12" => "PBKDF2",
        "1.3.6.1.4.1.11591.4.11" => "scrypt",
        "1.2.840.113549.2.7" => "HMAC-SHA1",
        "1.2.840.113549.2.9" => "HMAC-SHA256",
        "1.2.840.113549.2.10" => "HMAC-SHA384",
        "1.2.840.113549.2.11" => "HMAC-SHA512",
        "2.16.840.1.101.3.4.1.2" => "AES-128-CBC",
        "2.16.840.1.101.3.4.1.22" => "AES-192-CBC",
        "2.16.840.1.101.3.4.1.42" => "AES-256-CBC",
        "2.16.840.1.101.3.4.1.6" => "AES-128-GCM",
        "2.16.840.1.101.3.4.1.26" => "AES-192-GCM",
        "2.16.840.1.101.3.4.1.46" => "AES-256-GCM",
        "2.16.840.1.101.3.4.1.5" => "AES-128 key wrap",
        "2.16.840.1.101.3.4.1.45" => "AES-256 key wrap",
        "1.2.840.113549.3.7" => "3DES-CBC",
        "1.2.840.113549.1.12.1.3" => "PBE with SHA-1 and 3DES-CBC (legacy)",
        "1.2.840.113549.1.12.1.6" => "PBE with SHA-1 and 40-bit RC2-CBC (legacy, weak)",
        "1.3.14.3.2.26" => "SHA-1",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        "1.2.840.113549.1.7.1" => "data",
        "1.2.840.113549.1.7.2" => "signed data",
        "1.2.840.113549.1.7.3" => "enveloped data",
        "1.2.840.113549.1.7.6" => "encrypted data",
        "1.2.840.113549.1.9.16.1.23" => "authenticated enveloped data",
        "1.2.840.113549.1.12.10.1.1" => "key bag",
        "1.2.840.113549.1.12.10.1.2" => "encrypted key bag",
        "1.2.840.113549.1.12.10.1.3" => "certificate bag",
        _ => return None,
    })
}

/// An OID element as a name, or as dotted text when it is not one we know.
pub fn name_of(tlv: &Tlv) -> String {
    let dotted = oid_text(tlv.body);
    oid_name(&dotted).map(str::to_string).unwrap_or(dotted)
}

/// An AlgorithmIdentifier: the algorithm's OID, and its parameters if any.
pub fn algorithm<'a>(tlv: &Tlv<'a>) -> Option<(Tlv<'a>, Option<Tlv<'a>>)> {
    if tlv.tag != SEQUENCE {
        return None;
    }
    let parts = children(tlv.body)?;
    let oid = *parts.first().filter(|t| t.tag == OID)?;
    Some((oid, parts.get(1).copied()))
}

/// The bits of a positive INTEGER, as for an RSA modulus.
pub fn integer_bits(body: &[u8]) -> usize {
    let trimmed: &[u8] = match body.iter().position(|&b| b != 0) {
        Some(i) => &body[i..],
        None => return 0,
    };
    trimmed.len() * 8 - trimmed[0].leading_zeros() as usize
}

/// A public or private key's algorithm, told from its AlgorithmIdentifier and,
/// for RSA, the key itself: "RSA 2048 bits", "EC P-256", "Ed25519".
pub fn key_algorithm(alg: &Tlv, key: Option<&[u8]>) -> Option<String> {
    let (oid, params) = algorithm(alg)?;
    let name = name_of(&oid);
    Some(match name.as_str() {
        "EC" => match params.filter(|p| p.tag == OID) {
            Some(curve) => format!("EC {}", name_of(&curve)),
            None => "EC".to_string(),
        },
        "RSA" => match key.and_then(rsa_bits) {
            Some(bits) => format!("RSA {bits} bits"),
            None => "RSA".to_string(),
        },
        _ => name,
    })
}

/// The modulus size of an RSA key, public (SEQUENCE { n, e }) or private
/// (SEQUENCE { 0, n, e, … }).
pub fn rsa_bits(key: &[u8]) -> Option<usize> {
    let seq = whole(key).filter(|t| t.tag == SEQUENCE)?;
    let parts = children(seq.body)?;
    let n = match parts.as_slice() {
        [v, n, ..] if v.tag == INTEGER && v.body == [0] && parts.len() >= 9 => n,
        [n, e] if n.tag == INTEGER && e.tag == INTEGER => n,
        _ => return None,
    };
    (n.tag == INTEGER).then(|| integer_bits(n.body))
}
