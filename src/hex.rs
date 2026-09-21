//! Canonical hex: lowercase out, strictly lowercase in.
//!
//! One canonical form on purpose. Hex strings end up in
//! signed canonical byte forms and in fingerprint comparisons — two spellings
//! of the same bytes must not be able to exist. `decode` therefore rejects
//! uppercase instead of accepting it (fail-closed), and every consumer that
//! used to carry its own hex helper can drop it (nettls had two).

use crate::error::Error;

/// Encode bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode canonical (lowercase) hex. Fail-closed: odd length, uppercase or
/// any non-hex character is `Error::Format` — never a guess.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 {
        return Err(Error::Format(format!(
            "hex string has odd length {}",
            s.len()
        )));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
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
        _ => Err(Error::Format(format!(
            "invalid hex character {:?} — canonical hex is lowercase [0-9a-f]",
            c as char
        ))),
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
