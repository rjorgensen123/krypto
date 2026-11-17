// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical hex: lowercase out, strictly lowercase in.
//!
//! One canonical form on purpose. Hex strings end up in
//! signed canonical byte forms and in fingerprint comparisons — two spellings
//! of the same bytes must not be able to exist. `decode` therefore rejects
//! uppercase instead of accepting it (fail-closed), and every consumer that
//! used to carry its own hex helper can drop it (nettls had two).

use crate::error::Error;

const ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(ALPHABET[(b >> 4) as usize] as char);
        s.push(ALPHABET[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode canonical (lowercase) hex. Fail-closed: odd length, uppercase or
/// any non-hex character is `Error::Format` — never a guess. The output buffer
/// is reserved with `try_reserve_exact`: a failed reservation is
/// `Error::Hardening` instead of an abort (0.9.0); a length the system
/// promises but cannot back still fills the memory.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Format(format!(
            "hex string has odd length {}",
            s.len()
        )));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    out.try_reserve_exact(s.len() / 2).map_err(|_| {
        Error::Hardening(format!(
            "cannot allocate {} bytes for hex decode",
            s.len() / 2
        ))
    })?;
    let (pairs, _) = bytes.as_chunks::<2>();
    for pair in pairs {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        // Uppercase is rejected on purpose: canonical hex has ONE spelling.
        // The message names neither the character nor where it is (0.8.2):
        // the input may be a key, and either would tell something about it.
        _ => Err(Error::Format(
            "invalid hex character — canonical hex is lowercase [0-9a-f]".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = [0x00u8, 0x01, 0x7f, 0x80, 0xab, 0xff];
        let s = encode(&data);
        assert_eq!(s, "00017f80abff");
        assert_eq!(decode(&s).unwrap(), data);
    }

    #[test]
    fn empty_is_fine() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn odd_length_is_rejected() {
        assert!(matches!(decode("abc"), Err(Error::Format(_))));
    }

    #[test]
    fn uppercase_is_rejected() {
        assert!(matches!(decode("AB"), Err(Error::Format(_))));
        assert!(matches!(decode("aB"), Err(Error::Format(_))));
    }

    #[test]
    fn non_hex_is_rejected() {
        assert!(matches!(decode("zz"), Err(Error::Format(_))));
        assert!(matches!(decode("0 "), Err(Error::Format(_))));
    }
}
