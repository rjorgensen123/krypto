// SPDX-License-Identifier: MIT OR Apache-2.0
//! Small utilities every consumer was rolling on its own: plain SHA-256,
//! constant-time comparison, and randomness for values that are NOT secrets.
//! Also the crate's shared limit on an amount of data, [`MAX_DATA_BYTES`], and
//! the one path every request for random bytes in the crate takes (0.9.0).

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::Error;

/// The most data one input may hold, in bytes: 64 MiB (0.9.0). It bounds the
/// plaintext of `seal`, a blob (plus its header and tag), the data of
/// `hmac_sha256`, a message to sign or verify, the bytes `hex` and `base64`
/// encode or decode to, and the content of `SecretBuf::from_vec` and
/// `SecretString::from_string`. More is `Error::Format`.
pub const MAX_DATA_BYTES: usize = 64 * 1024 * 1024;

/// Refuses `len` above [`MAX_DATA_BYTES`] with `Error::Format` (0.9.0). `what`
/// names the input; the message carries only the lengths.
pub(crate) fn check_data_len(what: &str, len: usize) -> Result<(), Error> {
    if len > MAX_DATA_BYTES {
        return Err(Error::Format(format!(
            "{what} is {len} bytes — max {MAX_DATA_BYTES}"
        )));
    }
    Ok(())
}

/// Plain SHA-256 (FIPS 180-4). For fingerprints and content addressing —
/// **not** for authentication (use [`crate::hmac_sha256`]) and **not** for
/// passwords (use [`crate::password`]).
///
/// It has no size limit (0.9.0): it cannot fail and reserves no memory.
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
///
/// It has no size limit (0.9.0): it cannot fail and reserves no memory.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// The most bytes [`random_bytes`] and [`crate::SecretBuf::random`] give in
/// one call: 1 MiB (0.7.3). A program that needs more in one call states its
/// own cap with [`random_bytes_with_limit`] or
/// [`crate::SecretBuf::random_with_limit`].
pub const MAX_RANDOM_BYTES: usize = 1 << 20;

/// `len` bytes from the OS CSPRNG, for values that are **not secrets**:
/// salts, ids, jitter, nonce material a consumer manages itself.
///
/// The whole point of this function is the contrast with
/// [`crate::SecretBuf::random`]: a salt is *meant* to be stored in plaintext,
/// so wrapping it in a locked, redacted type would only obscure that. If the
/// value must stay secret, use `SecretBuf::random` instead.
///
/// At most [`MAX_RANDOM_BYTES`] per call; more is `Error::Format` (0.7.3).
pub fn random_bytes(len: usize) -> Result<Vec<u8>, Error> {
    random_bytes_with_limit(len, MAX_RANDOM_BYTES)
}

/// [`random_bytes`] with the caller's own cap for this call (0.7.3).
///
/// `len` above `limit` is `Error::Format`. Memory that cannot be had is
/// `Error::Hardening`, never a crash. A high `limit` is the caller's choice: a
/// length the system promises but cannot back still fills the memory.
pub fn random_bytes_with_limit(len: usize, limit: usize) -> Result<Vec<u8>, Error> {
    check_random_len(len, limit)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| Error::Hardening(format!("cannot allocate {len} random bytes")))?;
    out.resize(len, 0);
    fill_random(&mut out)?;
    Ok(out)
}

/// Set once `close_inherited_fds` has found that the random source no longer
/// answers (0.9.0), and never cleared: from then on krypto hands out no random
/// bytes in this process.
static RANDOM_SOURCE_CLOSED: AtomicBool = AtomicBool::new(false);

/// The answer to a request for random bytes once [`RANDOM_SOURCE_CLOSED`] is set.
fn random_source_closed_error() -> Error {
    Error::Hardening(
        "the random source was closed by close_inherited_fds; krypto hands out no random \
         bytes in this process any more"
            .into(),
    )
}

/// `Error::Hardening` once `close_inherited_fds` has found the random source
/// closed (0.9.0). For a caller that lets a dependency draw the random bytes
/// itself, such as the salt in `password::hash`.
pub(crate) fn check_random_source_open() -> Result<(), Error> {
    if RANDOM_SOURCE_CLOSED.load(Ordering::SeqCst) {
        return Err(random_source_closed_error());
    }
    Ok(())
}

/// Fill `buf` from the OS CSPRNG (0.9.0). Every request for random bytes
/// krypto makes itself goes through here, so none is answered once
/// `close_inherited_fds` has found the random source closed.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    check_random_source_open()?;
    getrandom::fill(buf).map_err(|e| Error::Hardening(format!("getrandom failed: {e}")))
}

/// Ask the random source for one byte after `close_inherited_fds` has closed
/// the descriptors (0.9.0). Where the source reads through a descriptor that
/// was open before, it no longer answers: the flag is set and the call is
/// `Error::Hardening`. Once the flag is set the source is not asked again,
/// since its number may now belong to another file, which would answer.
pub(crate) fn probe_random_source_after_close() -> Result<(), Error> {
    check_random_source_open()?;
    let mut byte = [0u8; 1];
    getrandom::fill(&mut byte).map_err(|e| {
        RANDOM_SOURCE_CLOSED.store(true, Ordering::SeqCst);
        Error::Hardening(format!(
            "the random source does not answer after the descriptors were closed: {e}; krypto \
             hands out no random bytes in this process from now on; the usual cause is that \
             something asked for random bytes before close_inherited_fds was called"
        ))
    })
}

/// `Error::Format` if `len` is above the cap for this call.
pub(crate) fn check_random_len(len: usize, limit: usize) -> Result<(), Error> {
    if len > limit {
        return Err(Error::Format(format!(
            "{len} random bytes asked for; the cap for this call is {limit}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 known answers ("abc" and the empty string).
    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            crate::hex::encode(&sha256(b"abc")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            crate::hex::encode(&sha256(b"")).unwrap(),
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
