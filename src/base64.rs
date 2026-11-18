// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical base64 (STANDARD alphabet): one spelling out, strictly that
//! spelling in.
//!
//! Same philosophy as [`crate::hex`]: one canonical implementation, checked
//! against Python's standard library in `krypto-py/tests/test_independent.py`.
//! NOTE: keys and signatures on the wire are HEX (the canon) — base64
//! exists only for formats that ARE base64 by nature (the ssh fingerprint
//! form `SHA256:<base64-no-pad>`, PEM bodies).
//!
//! `decode`/`decode_nopad` are fail-closed: whitespace, invalid characters,
//! wrong padding and non-zero discarded trailing bits are all `Error::Format`
//! — two spellings of the same bytes must not be able to exist.

use crate::error::Error;
use crate::util::{check_data_len, MAX_DATA_BYTES};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The longest text [`decode`] takes, in bytes: the padded base64 of
/// [`MAX_DATA_BYTES`] bytes (0.9.0).
const MAX_TEXT_BYTES: usize = MAX_DATA_BYTES.div_ceil(3) * 4;

/// The longest text [`decode_nopad`] takes, in bytes: the unpadded base64 of
/// [`MAX_DATA_BYTES`] bytes (0.9.0).
const MAX_NOPAD_TEXT_BYTES: usize = (4 * MAX_DATA_BYTES).div_ceil(3);

/// Refuses text longer than `max` with `Error::Format` (0.9.0).
fn check_text_len(s: &str, max: usize) -> Result<(), Error> {
    if s.len() > max {
        return Err(Error::Format(format!(
            "base64 string is {} bytes — max {max}",
            s.len()
        )));
    }
    Ok(())
}

/// Encode bytes as STANDARD base64 **with** padding (PEM-style body form).
///
/// `bytes` is at most [`MAX_DATA_BYTES`]; more is `Error::Format`, refused
/// before any memory is reserved (0.9.0). The output string is reserved with
/// `try_reserve_exact`: a failed reservation is `Error::Hardening` instead of
/// an abort.
pub fn encode(bytes: &[u8]) -> Result<String, Error> {
    check_data_len("base64 encode input", bytes.len())?;
    let len = bytes.len().div_ceil(3) * 4;
    let mut out = String::new();
    out.try_reserve_exact(len)
        .map_err(|_| Error::Hardening(format!("cannot allocate {len} bytes for base64 encode")))?;
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
    Ok(out)
}

/// Encode bytes as STANDARD base64 **without** padding (the ssh fingerprint
/// form `SHA256:<base64-no-pad>`). The limit and the errors are those of
/// [`encode`] (0.9.0).
pub fn encode_nopad(bytes: &[u8]) -> Result<String, Error> {
    let mut s = encode(bytes)?;
    while s.ends_with('=') {
        s.pop();
    }
    Ok(s)
}

/// Decode canonical padded base64. Fail-closed: whitespace, invalid
/// characters, missing/misplaced padding or non-zero discarded trailing bits
/// are `Error::Format` — never a guess. The output buffer is reserved with
/// `try_reserve_exact`: a failed reservation is `Error::Hardening` instead of
/// an abort (0.9.0); a length the system promises but cannot back still fills
/// the memory.
///
/// The output is at most [`MAX_DATA_BYTES`] (0.9.0): `s` longer than the
/// padded base64 of that many bytes is `Error::Format`, refused before
/// anything else, and so is an `s` of that length that would decode to more.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    check_text_len(s, MAX_TEXT_BYTES)?;
    if !s.len().is_multiple_of(4) {
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
/// padding characters are rejected — the unpadded form has ONE spelling — and,
/// as in [`decode`], what is rejected is `Error::Format`. The output buffer is
/// reserved with `try_reserve_exact`: a failed reservation is
/// `Error::Hardening` instead of an abort (0.9.0); a length the system
/// promises but cannot back still fills the memory.
///
/// The output is at most [`MAX_DATA_BYTES`] (0.9.0): `s` longer than the
/// unpadded base64 of that many bytes is `Error::Format`, refused before
/// anything else.
pub fn decode_nopad(s: &str) -> Result<Vec<u8>, Error> {
    check_text_len(s, MAX_NOPAD_TEXT_BYTES)?;
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
    // The limit is on the output (0.9.0): a padded text of the longest length
    // with one `=` or none would decode to one or two bytes more.
    let out_len = s.len() / 4 * 3 + s.len() % 4 * 3 / 4;
    if out_len > MAX_DATA_BYTES {
        return Err(Error::Format(format!(
            "base64 string decodes to {out_len} bytes — max {MAX_DATA_BYTES}"
        )));
    }
    // The output buffer is reserved with `try_reserve_exact`: a failed
    // reservation is `Error::Hardening` instead of an abort (0.9.0); a length
    // the system promises but cannot back still fills the memory.
    let cap = s.len() / 4 * 3 + 2;
    let mut out = Vec::new();
    out.try_reserve_exact(cap)
        .map_err(|_| Error::Hardening(format!("cannot allocate {cap} bytes for base64 decode")))?;
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
        // The message names neither the character nor where it is (0.8.2):
        // the input may be secret, and either would tell something about it.
        _ => Err(Error::Format(
            "invalid base64 character (STANDARD alphabet, no whitespace)".into(),
        )),
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
            let p = encode(data).unwrap();
            assert_eq!(decode(&p).unwrap(), data);
            let n = encode_nopad(data).unwrap();
            assert_eq!(decode_nopad(&n).unwrap(), data);
        }
    }

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10 — the published answers, not just a roundtrip.
        assert_eq!(encode(b"foobar").unwrap(), "Zm9vYmFy");
        assert_eq!(encode(b"fooba").unwrap(), "Zm9vYmE=");
        assert_eq!(encode(b"foob").unwrap(), "Zm9vYg==");
        assert_eq!(encode_nopad(b"fooba").unwrap(), "Zm9vYmE");
    }

    #[test]
    fn whitespace_and_invalid_rejected() {
        assert!(matches!(decode("Zm9v YmFy"), Err(Error::Format(_))));
        assert!(matches!(decode("Zm9v\nYmFy"), Err(Error::Format(_))));
        assert!(matches!(decode_nopad("Zm9v!"), Err(Error::Format(_))));
    }

    #[test]
    fn padding_rules_are_strict() {
        assert!(matches!(decode("Zm9vYmE"), Err(Error::Format(_)))); // missing padding
        assert!(matches!(decode_nopad("Zm9vYmE="), Err(Error::Format(_)))); // has padding
        assert!(matches!(decode("Zm9vY==="), Err(Error::Format(_)))); // too much padding
    }

    #[test]
    fn non_canonical_trailing_bits_rejected() {
        // "Zm9vYmF=" would decode to the same bytes as "Zm9vYmE=" if the
        // discarded bits were ignored — two spellings of one value, refused.
        assert!(matches!(decode("Zm9vYmF="), Err(Error::Format(_))));
        assert!(matches!(decode_nopad("Zm9vYmF"), Err(Error::Format(_))));
    }
}
