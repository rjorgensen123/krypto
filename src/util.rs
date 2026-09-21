//! Small utilities every consumer was rolling on its own: plain SHA-256,
//! constant-time comparison, and randomness for values that are NOT secrets.

use crate::error::Error;

/// Plain SHA-256 (FIPS 180-4). For fingerprints and content addressing —
/// **not** for authentication (use [`crate::hmac_sha256`]) and **not** for
/// passwords (use [`crate::password`]).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Constant-time equality for byte slices.
///
/// Use wherever one side of the comparison is secret-derived (MACs,
/// fingerprints against a pin, key ids) — a plain `==` can leak how many
/// leading bytes matched through timing. Slices of different length compare
/// unequal immediately; the *length* is treated as public.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// `len` bytes from the OS CSPRNG, for values that are **not secrets**:
/// salts, ids, jitter, nonce material a consumer manages itself.
///
/// The whole point of this function is the contrast with
/// [`crate::SecretBuf::random`]: a salt is *meant* to be stored in plaintext,
/// so wrapping it in a locked, redacted type would only obscure that. If the
/// value must stay secret, use `SecretBuf::random` instead.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out)
        .map_err(|e| Error::Hardening(format!("getrandom failed: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 known answers ("abc" and the empty string).
    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            crate::hex::encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            crate::hex::encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq(b"same", b"same"));
        assert!(!ct_eq(b"same", b"sane"));
        assert!(!ct_eq(b"short", b"longer"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn random_bytes_length_and_variation() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "two random draws should (almost surely) differ");
    }
}
