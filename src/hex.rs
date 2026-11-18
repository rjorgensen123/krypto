// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical hex: lowercase out, strictly lowercase in.
//!
//! One canonical form on purpose. Hex strings end up in
//! signed canonical byte forms and in fingerprint comparisons — two spellings
//! of the same bytes must not be able to exist. `decode` therefore rejects
//! uppercase instead of accepting it (fail-closed), and every consumer that
//! used to carry its own hex helper can drop it (nettls had two).

use crate::error::Error;
use crate::util::{check_data_len, MAX_DATA_BYTES};

const ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// The longest text [`decode`] takes, in bytes: the hex of
/// [`MAX_DATA_BYTES`] bytes (0.9.0).
const MAX_TEXT_BYTES: usize = 2 * MAX_DATA_BYTES;

/// Encode bytes as lowercase hex.
///
/// `bytes` is at most [`MAX_DATA_BYTES`]; more is `Error::Format`, refused
/// before any memory is reserved (0.9.0). The output string is reserved with
/// `try_reserve_exact`: a failed reservation is `Error::Hardening` instead of
/// an abort.
pub fn encode(bytes: &[u8]) -> Result<String, Error> {
    check_data_len("hex encode input", bytes.len())?;
    let len = bytes.len() * 2;
    let mut s = String::new();
    s.try_reserve_exact(len)
        .map_err(|_| Error::Hardening(format!("cannot allocate {len} bytes for hex encode")))?;
    for &b in bytes {
        s.push(ALPHABET[(b >> 4) as usize] as char);
        s.push(ALPHABET[(b & 0x0f) as usize] as char);
    }
    Ok(s)
}

/// Decode canonical (lowercase) hex. Fail-closed: odd length, uppercase or
/// any non-hex character is `Error::Format` — never a guess. The output buffer
/// is reserved with `try_reserve_exact`: a failed reservation is
/// `Error::Hardening` instead of an abort (0.9.0); a length the system
/// promises but cannot back still fills the memory.
///
/// The output is at most [`MAX_DATA_BYTES`], so `s` is at most twice that; a
/// longer `s` is `Error::Format`, refused before anything else (0.9.0).
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() > MAX_TEXT_BYTES {
        return Err(Error::Format(format!(
            "hex string is {} bytes — max {MAX_TEXT_BYTES}",
            s.len()
        )));
    }
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
        let s = encode(&data).unwrap();
        assert_eq!(s, "00017f80abff");
        assert_eq!(decode(&s).unwrap(), data);
    }

    #[test]
    fn empty_is_fine() {
        assert_eq!(encode(&[]).unwrap(), "");
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
