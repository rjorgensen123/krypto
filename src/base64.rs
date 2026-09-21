// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical base64 (STANDARD alphabet): one spelling out, strictly that
//! spelling in.
//!
//! Same philosophy as [`crate::hex`]: one canonical implementation, with the
//! Python parity guarantee via krypto-cli. NOTE: keys and signatures on the
//! wire are HEX (the canon) — base64
//! exists only for formats that ARE base64 by nature (the ssh fingerprint
//! form `SHA256:<base64-no-pad>`, PEM bodies).
//!
//! `decode`/`decode_nopad` are fail-closed: whitespace, invalid characters,
//! wrong padding and non-zero discarded trailing bits are all `Error::Format`
//! — two spellings of the same bytes must not be able to exist.

use crate::error::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as STANDARD base64 **with** padding (PEM-style body form).
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Encode bytes as STANDARD base64 **without** padding (the ssh fingerprint
/// form `SHA256:<base64-no-pad>`).
pub fn encode_nopad(bytes: &[u8]) -> String {
    let mut s = encode(bytes);
    while s.ends_with('=') {
        s.pop();
    }
    s
}

/// Decode canonical padded base64. Fail-closed: whitespace, invalid
/// characters, missing/misplaced padding or non-zero discarded trailing bits
/// are `Error::Format` — never a guess.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 4 != 0 {
        return Err(Error::Format(format!(
            "base64 length {} is not a multiple of 4 (padded form required)",
            s.len()
        )));
    }
    let stripped = s.trim_end_matches('=');
    let pad = s.len() - stripped.len();
    if pad > 2 {
        return Err(Error::Format("too much base64 padding".into()));
    }
    decode_body(stripped)
}

/// Decode canonical unpadded base64 (ssh fingerprint form). Fail-closed:
/// padding characters are rejected — the unpadded form has ONE spelling.
pub fn decode_nopad(s: &str) -> Result<Vec<u8>, Error> {
    if s.contains('=') {
        return Err(Error::Format(
            "unexpected '=' — decode_nopad takes the unpadded form".into(),
        ));
    }
    if s.len() % 4 == 1 {
        return Err(Error::Format(format!(
            "impossible base64 length {} (mod 4 == 1)",
            s.len()
        )));
    }
    decode_body(s)
}

/// Decode the alphabet body (no padding chars). Rejects invalid characters
/// and non-zero discarded bits in the final quantum (canonical: one spelling).
fn decode_body(s: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in s.as_bytes() {
        let v = sextet(c)?;
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    // Canonical: the discarded trailing bits must be zero, otherwise two
    // different strings would decode to the same bytes.
    if nbits > 0 && acc != 0 {
        return Err(Error::Format(
            "non-canonical base64: trailing bits are not zero".into(),
        ));
    }
    Ok(out)
}

fn sextet(c: u8) -> Result<u8, Error> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        // Whitespace too: canonical base64 has ONE spelling, unbroken.
        _ => Err(Error::Format(format!(
            "invalid base64 character {:?} (STANDARD alphabet, no whitespace)",
            c as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_padded_and_nopad() {
        for data in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &b"foob"[..],
            &b"fooba"[..],
            &b"foobar"[..],
            &[0x00, 0xff, 0x7f, 0x80][..],
        ] {
            let p = encode(data);
            assert_eq!(decode(&p).unwrap(), data);
            let n = encode_nopad(data);
            assert_eq!(decode_nopad(&n).unwrap(), data);
        }
    }

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10 — the published answers, not just a roundtrip.
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode_nopad(b"fooba"), "Zm9vYmE");
    }

    #[test]
    fn whitespace_and_invalid_rejected() {
        assert!(matches!(decode("Zm9v YmFy"), Err(Error::Format(_))));
        assert!(matches!(decode("Zm9v\nYmFy"), Err(Error::Format(_))));
        assert!(matches!(decode_nopad("Zm9v!"), Err(Error::Format(_))));
    }

    #[test]
    fn padding_rules_are_strict() {
        assert!(matches!(decode("Zm9vYmE"), Err(Error::Format(_)))); // mangler pad
        assert!(matches!(decode_nopad("Zm9vYmE="), Err(Error::Format(_)))); // har pad
        assert!(matches!(decode("Zm9vY==="), Err(Error::Format(_)))); // for mye pad
    }

    #[test]
    fn non_canonical_trailing_bits_rejected() {
        // "Zm9vYmF=" would decode to the same bytes as "Zm9vYmE=" if the
        // discarded bits were ignored — two spellings of one value, refused.
        assert!(matches!(decode("Zm9vYmF="), Err(Error::Format(_))));
        assert!(matches!(decode_nopad("Zm9vYmF"), Err(Error::Format(_))));
    }
}
