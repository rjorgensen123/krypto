//! X25519 key agreement (RFC 7748) — the primitive under sealed envelopes.
//!
//! krypto provides the *primitive*; the envelope **format** (header, AAD
//! layout, magic) belongs to the consumer — nettls's `NETENV` envelope is
//! built from exactly this plus krypto's HKDF and AEAD. Private keys cross
//! the API only as [`SecretBuf`]; the shared
//! secret comes back as a [`SecretBuf`] and should be fed through
//! [`crate::MasterKey::derive`] (HKDF) before use — never used raw as a key.

use crate::error::Error;
use crate::secret::SecretBuf;

/// Length of a raw X25519 private or public key.
pub const X25519_KEY_LEN: usize = 32;

fn static_secret(secret: &SecretBuf) -> Result<x25519_dalek::StaticSecret, Error> {
    secret.expose(|b| {
        let arr: [u8; X25519_KEY_LEN] = b.try_into().map_err(|_| {
            Error::Format(format!(
                "an X25519 private key must be {X25519_KEY_LEN} bytes, got {}",
                b.len()
            ))
        })?;
        Ok(x25519_dalek::StaticSecret::from(arr))
    })
}

/// New X25519 keypair: (private, public), both raw 32 bytes.
pub fn x25519_keypair() -> Result<(SecretBuf, [u8; X25519_KEY_LEN]), Error> {
    let secret = SecretBuf::random(X25519_KEY_LEN)?;
    let public = x25519_public(&secret)?;
    Ok((secret, public))
}

/// The public key that belongs to an X25519 private key.
pub fn x25519_public(secret: &SecretBuf) -> Result<[u8; X25519_KEY_LEN], Error> {
    let s = static_secret(secret)?;
    Ok(*x25519_dalek::PublicKey::from(&s).as_bytes())
}

/// Diffie-Hellman: our private key × the peer's public key → shared secret.
///
/// Rejects a non-contributory result (an all-zero shared secret from a
/// low-order peer point) with `Error::Auth` — accepting it would let a
/// malicious peer force a predictable key. The result is keying *material*:
/// run it through HKDF ([`crate::MasterKey::derive`]) before use.
pub fn x25519_shared(secret: &SecretBuf, peer_public: &[u8]) -> Result<SecretBuf, Error> {
    let s = static_secret(secret)?;
    let pk: [u8; X25519_KEY_LEN] = peer_public.try_into().map_err(|_| {
        Error::Format(format!(
            "an X25519 public key must be {X25519_KEY_LEN} bytes, got {}",
            peer_public.len()
        ))
    })?;
    let shared = s.diffie_hellman(&x25519_dalek::PublicKey::from(pk));
    if !shared.was_contributory() {
        return Err(Error::Auth);
    }
    SecretBuf::from_vec(shared.as_bytes().to_vec())
}
