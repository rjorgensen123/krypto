// SPDX-License-Identifier: MIT OR Apache-2.0
//! X.509 and PKCS: certificates, requests and revocation lists, private and
//! public keys, PKCS#12 bundles and CMS (S/MIME). Told from the DER structure
//! and the OIDs in it.

use super::der::{self, Tlv, BIT_STRING, INTEGER, OCTET_STRING, OID, SEQUENCE};
use super::Finding;

/// Any of the structures below, from DER.
pub fn from_der(input: &[u8]) -> Option<Finding> {
    let outer = der::whole(input).filter(|t| t.tag == SEQUENCE)?;
    let parts = der::children(outer.body)?;
    certificate(&parts)
        .or_else(|| request(&parts))
        .or_else(|| revocation_list(&parts))
        .or_else(|| pkcs8(&parts))
        .or_else(|| encrypted_pkcs8(&parts))
        .or_else(|| spki(&parts))
        .or_else(|| pkcs12(&parts))
        .or_else(|| cms(&parts))
        .or_else(|| sec1(&parts))
        .or_else(|| pkcs1_private(&parts))
}

/// SEQUENCE { tbsCertificate, signatureAlgorithm, signature }.
fn certificate(parts: &[Tlv]) -> Option<Finding> {
    let [tbs, sig_alg, sig] = parts else {
        return None;
    };
    if tbs.tag != SEQUENCE || sig.tag != BIT_STRING {
        return None;
    }
    let tbs = der::children(tbs.body)?;
    // [0] version is there from v2 on; the rest is serial, signature,
    // issuer, validity, subject, subjectPublicKeyInfo.
    let fields = if tbs.first()?.tag == 0xa0 {
        &tbs[1..]
    } else {
        &tbs[..]
    };
    let [serial, _, _, validity, _, spki, ..] = fields else {
        return None;
    };
    if serial.tag != INTEGER || validity.tag != SEQUENCE {
        return None;
    }
    let times = der::children(validity.body)?;
    let [from, until] = times.as_slice() else {
        return None;
    };
    let mut found = Finding::new("X.509 certificate")
        .fact("signature", signature_name(sig_alg)?)
        .fact(
            "public key",
            spki_key(spki).unwrap_or_else(|| "unknown".into()),
        );
    if let (Some(from), Some(until)) = (time(from), time(until)) {
        found = found.fact("valid", format!("{from} to {until}"));
    }
    Some(found)
}

/// `SEQUENCE { certificationRequestInfo { 0, subject, spki, [0] }, alg, sig }`.
fn request(parts: &[Tlv]) -> Option<Finding> {
    let [info, sig_alg, sig] = parts else {
        return None;
    };
    if info.tag != SEQUENCE || sig.tag != BIT_STRING {
        return None;
    }
    let info = der::children(info.body)?;
    let [version, _, spki, ..] = info.as_slice() else {
        return None;
    };
    if version.tag != INTEGER || version.body != [0] || spki.tag != SEQUENCE {
        return None;
    }
    Some(
        Finding::new("certificate signing request (PKCS#10)")
            .fact("signature", signature_name(sig_alg)?)
            .fact("public key", spki_key(spki)?),
    )
}

/// `SEQUENCE { tbsCertList { [version], signature, issuer, thisUpdate, … }, alg, sig }`.
fn revocation_list(parts: &[Tlv]) -> Option<Finding> {
    let [tbs, sig_alg, sig] = parts else {
        return None;
    };
    if tbs.tag != SEQUENCE || sig.tag != BIT_STRING {
        return None;
    }
    let tbs = der::children(tbs.body)?;
    let fields = if tbs.first()?.tag == INTEGER {
        &tbs[1..]
    } else {
        &tbs[..]
    };
    let [alg, issuer, this_update, ..] = fields else {
        return None;
    };
    if alg.tag != SEQUENCE || issuer.tag != SEQUENCE || time(this_update).is_none() {
        return None;
    }
    Some(
        Finding::new("certificate revocation list (X.509 CRL)")
            .fact("signature", signature_name(sig_alg)?),
    )
}

/// SEQUENCE { version 0 or 1, algorithm, OCTET STRING privateKey, … }.
fn pkcs8(parts: &[Tlv]) -> Option<Finding> {
    let [version, alg, key, ..] = parts else {
        return None;
    };
    if version.tag != INTEGER
        || version.body.len() != 1
        || version.body[0] > 1
        || key.tag != OCTET_STRING
    {
        return None;
    }
    let what = der::key_algorithm(alg, Some(key.body))?;
    Some(
        Finding::new("private key (PKCS#8)")
            .fact("algorithm", what)
            .fact("key", "not shown"),
    )
}

/// SEQUENCE { encryptionAlgorithm, OCTET STRING encryptedData }.
fn encrypted_pkcs8(parts: &[Tlv]) -> Option<Finding> {
    let [alg, data] = parts else { return None };
    if data.tag != OCTET_STRING {
        return None;
    }
    let (oid, params) = der::algorithm(alg)?;
    let scheme = der::name_of(&oid);
    let mut found = Finding::new("encrypted private key (PKCS#8)");
    if scheme == "PBES2" {
        let (kdf, cipher) = pbes2(params?)?;
        found = found.fact("key from", kdf).fact("cipher", cipher);
    } else {
        found = found.fact("scheme", scheme);
    }
    Some(found)
}

/// PBES2 parameters: SEQUENCE { keyDerivationFunc, encryptionScheme }.
fn pbes2(params: Tlv) -> Option<(String, String)> {
    let parts = der::children(params.body)?;
    let [kdf, cipher] = parts.as_slice() else {
        return None;
    };
    let (kdf_oid, kdf_params) = der::algorithm(kdf)?;
    let (cipher_oid, _) = der::algorithm(cipher)?;
    let kdf_name = der::name_of(&kdf_oid);
    let kdf_text = match (kdf_name.as_str(), kdf_params) {
        ("PBKDF2", Some(p)) => {
            let fields = der::children(p.body)?;
            let iterations = fields
                .get(1)
                .filter(|t| t.tag == INTEGER)
                .map(|t| t.body.iter().fold(0u64, |a, &b| (a << 8) | b as u64));
            let prf = fields
                .iter()
                .find(|t| t.tag == SEQUENCE)
                .and_then(|t| der::algorithm(t))
                .map(|(o, _)| der::name_of(&o))
                .unwrap_or_else(|| "HMAC-SHA1".into());
            match iterations {
                Some(n) => format!("PBKDF2 with {prf}, {n} iterations"),
                None => format!("PBKDF2 with {prf}"),
            }
        }
        (name, _) => name.to_string(),
    };
    Some((kdf_text, der::name_of(&cipher_oid)))
}

/// SEQUENCE { algorithm, BIT STRING subjectPublicKey }.
fn spki(parts: &[Tlv]) -> Option<Finding> {
    let [alg, key] = parts else { return None };
    if key.tag != BIT_STRING {
        return None;
    }
    let what = der::key_algorithm(alg, key.body.get(1..))?;
    Some(Finding::new("public key (SubjectPublicKeyInfo)").fact("algorithm", what))
}

fn spki_key(spki: &Tlv) -> Option<String> {
    let parts = der::children(spki.body)?;
    let [alg, key] = parts.as_slice() else {
        return None;
    };
    der::key_algorithm(alg, key.body.get(1..))
}

/// `SEQUENCE { 1, OCTET STRING privateKey, [0] curve, [1] publicKey }` (RFC 5915).
fn sec1(parts: &[Tlv]) -> Option<Finding> {
    let [version, key, rest @ ..] = parts else {
        return None;
    };
    if version.tag != INTEGER || version.body != [1] || key.tag != OCTET_STRING {
        return None;
    }
    let curve = rest
        .iter()
        .find(|t| t.tag == 0xa0)
        .and_then(|t| der::whole(t.body))
        .filter(|t| t.tag == OID)
        .map(|t| der::name_of(&t))
        .unwrap_or_else(|| "curve not named".into());
    Some(
        Finding::new("EC private key (SEC1)")
            .fact("algorithm", format!("EC {curve}"))
            .fact("key", "not shown"),
    )
}

/// SEQUENCE { 0, n, e, d, p, q, dp, dq, qinv } (PKCS#1).
fn pkcs1_private(parts: &[Tlv]) -> Option<Finding> {
    if parts.len() != 9 || parts.iter().any(|t| t.tag != INTEGER) || parts[0].body != [0] {
        return None;
    }
    let bits = der::integer_bits(parts[1].body);
    Some(
        Finding::new("RSA private key (PKCS#1)")
            .fact("algorithm", format!("RSA {bits} bits"))
            .fact("key", "not shown"),
    )
}

/// A PKCS#1 public key, SEQUENCE { n, e }: only under its PEM label, since the
/// shape alone is too common.
pub fn pkcs1_public(input: &[u8]) -> Option<Finding> {
    let bits = der::rsa_bits(input)?;
    Some(Finding::new("RSA public key (PKCS#1)").fact("algorithm", format!("RSA {bits} bits")))
}

/// SEQUENCE { 3, ContentInfo authSafe, macData }.
fn pkcs12(parts: &[Tlv]) -> Option<Finding> {
    let [version, auth_safe, rest @ ..] = parts else {
        return None;
    };
    if version.tag != INTEGER || version.body != [3] || auth_safe.tag != SEQUENCE {
        return None;
    }
    let mut found = Finding::new("PKCS#12 bundle (PFX)");
    if let Some(mac) = rest.first().and_then(mac_data) {
        found = found.fact("integrity", mac);
    }
    let protection = pkcs12_protection(auth_safe).unwrap_or_default();
    if !protection.is_empty() {
        found = found.fact("encryption", protection.join("; "));
    }
    Some(found)
}

/// macData: SEQUENCE { DigestInfo { algorithm, digest }, salt, iterations }.
fn mac_data(mac: &Tlv) -> Option<String> {
    let parts = der::children(mac.body)?;
    let digest_info = der::children(parts.first()?.body)?;
    let (oid, _) = der::algorithm(digest_info.first()?)?;
    let iterations = parts
        .get(2)
        .filter(|t| t.tag == INTEGER)
        .map(|t| t.body.iter().fold(0u64, |a, &b| (a << 8) | b as u64));
    Some(match iterations {
        Some(n) => format!("HMAC with {}, {n} iterations", der::name_of(&oid)),
        None => format!("HMAC with {}", der::name_of(&oid)),
    })
}

/// How the bags inside a PKCS#12 bundle are protected.
fn pkcs12_protection(auth_safe: &Tlv) -> Option<Vec<String>> {
    let content = content_of(auth_safe, "data")?;
    let octets = der::whole(content).filter(|t| t.tag == OCTET_STRING)?;
    let infos = der::whole(octets.body).filter(|t| t.tag == SEQUENCE)?;
    let mut out = Vec::new();
    for info in der::children(infos.body)? {
        let parts = der::children(info.body)?;
        let kind = der::name_of(parts.first()?);
        let inner = parts.get(1).and_then(|t| der::whole(t.body))?;
        match kind.as_str() {
            "encrypted data" => {
                let fields = der::children(inner.body)?;
                let eci = der::children(fields.get(1)?.body)?;
                out.push(format!("certificates: {}", scheme_text(eci.get(1)?)?));
            }
            "data" => {
                let bags = der::whole(inner.body).filter(|t| t.tag == SEQUENCE)?;
                for bag in der::children(bags.body)? {
                    let bag_parts = der::children(bag.body)?;
                    if der::name_of(bag_parts.first()?) == "encrypted key bag" {
                        let value = der::whole(bag_parts.get(1)?.body)?;
                        let key = der::children(value.body)?;
                        out.push(format!("private key: {}", scheme_text(key.first()?)?));
                    }
                }
            }
            _ => {}
        }
    }
    Some(out)
}

fn scheme_text(alg: &Tlv) -> Option<String> {
    let (oid, params) = der::algorithm(alg)?;
    let name = der::name_of(&oid);
    if name == "PBES2" {
        let (kdf, cipher) = pbes2(params?)?;
        Some(format!("{cipher}, key from {kdf}"))
    } else {
        Some(name)
    }
}

/// The content of a `ContentInfo { OID, [0] content }` of the given type.
fn content_of<'a>(info: &Tlv<'a>, kind: &str) -> Option<&'a [u8]> {
    let parts = der::children(info.body)?;
    let [oid, content] = parts.as_slice() else {
        return None;
    };
    (oid.tag == OID && der::name_of(oid) == kind && content.tag == 0xa0).then_some(content.body)
}

/// CMS / PKCS#7: `ContentInfo { OID contentType, [0] content }`.
fn cms(parts: &[Tlv]) -> Option<Finding> {
    let [oid, content] = parts else { return None };
    if oid.tag != OID || content.tag != 0xa0 {
        return None;
    }
    let kind = der::name_of(oid);
    let inner = der::whole(content.body).filter(|t| t.tag == SEQUENCE)?;
    let fields = der::children(inner.body)?;
    match kind.as_str() {
        "enveloped data" | "authenticated enveloped data" => {
            let eci = fields.iter().rev().find(|t| t.tag == SEQUENCE)?;
            let eci = der::children(eci.body)?;
            let cipher = der::algorithm(eci.get(1)?).map(|(o, _)| der::name_of(&o))?;
            let recipients = fields
                .iter()
                .find(|t| t.tag == der::SET)
                .and_then(|set| der::children(set.body))
                .map(|r| {
                    r.iter()
                        .filter_map(recipient)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let mut found =
                Finding::new(format!("CMS {kind} (S/MIME, PKCS#7)")).fact("cipher", cipher);
            if !recipients.is_empty() {
                found = found.fact("recipients", recipients);
            }
            Some(found)
        }
        "signed data" => {
            let digests = fields
                .iter()
                .find(|t| t.tag == der::SET)
                .and_then(|set| der::children(set.body))
                .map(|d| {
                    d.iter()
                        .filter_map(|a| der::algorithm(a))
                        .map(|(o, _)| der::name_of(&o))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let signers = fields
                .iter()
                .rev()
                .find(|t| t.tag == der::SET)
                .and_then(|set| der::children(set.body))
                .map(|s| s.iter().filter_map(signer).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            let mut found =
                Finding::new("CMS signed data (S/MIME, PKCS#7)").fact("digest", digests.join(", "));
            if !signers.is_empty() {
                found = found.fact("signature", signers);
            }
            Some(found)
        }
        "encrypted data" => {
            let eci = der::children(fields.get(1)?.body)?;
            Some(
                Finding::new("CMS encrypted data (PKCS#7)")
                    .fact("encryption", scheme_text(eci.get(1)?)?),
            )
        }
        _ => None,
    }
}

/// A RecipientInfo: the key transport or agreement algorithm.
fn recipient(info: &Tlv) -> Option<String> {
    let parts = der::children(info.body)?;
    // ktri: SEQUENCE { version, rid, keyEncryptionAlgorithm, encryptedKey }
    if info.tag == SEQUENCE {
        let alg = parts.iter().find(|t| der::algorithm(t).is_some())?;
        return der::algorithm(alg)
            .map(|(o, _)| format!("key transport with {}", der::name_of(&o)));
    }
    // kari [1], kekri [2], pwri [3]
    Some(match info.tag {
        0xa1 => "key agreement".to_string(),
        0xa2 => "key encryption key".to_string(),
        0xa3 => "password".to_string(),
        _ => return None,
    })
}

/// A SignerInfo: its signature algorithm.
fn signer(info: &Tlv) -> Option<String> {
    let parts = der::children(info.body)?;
    // version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
    let algs: Vec<_> = parts.iter().filter_map(|t| der::algorithm(t)).collect();
    algs.get(1).map(|(o, _)| der::name_of(o))
}

fn signature_name(alg: &Tlv) -> Option<String> {
    der::algorithm(alg).map(|(oid, _)| der::name_of(&oid))
}

/// UTCTime or GeneralizedTime as YYYY-MM-DD.
fn time(t: &Tlv) -> Option<String> {
    let s = std::str::from_utf8(t.body).ok()?;
    let digits =
        |r: std::ops::Range<usize>| s.get(r).filter(|d| d.bytes().all(|b| b.is_ascii_digit()));
    match t.tag {
        0x17 => {
            let yy: u32 = digits(0..2)?.parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            Some(format!("{year}-{}-{}", digits(2..4)?, digits(4..6)?))
        }
        0x18 => Some(format!(
            "{}-{}-{}",
            digits(0..4)?,
            digits(4..6)?,
            digits(6..8)?
        )),
        _ => None,
    }
}
