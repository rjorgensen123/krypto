//! Signatures: Ed25519 (raw keys) and ECDSA P-256 (PKCS#8 / SEC1 / DER).
//!
//! Exists so no consumer rolls its own signature layer — nettls went straight
//! to `ring` for exactly this. The forms are chosen to
//! match the forms already in common use:
//!
//! - **Ed25519**: raw 32-byte seed and raw 32-byte public key, 64-byte
//!   signature — the form public keys are usually distributed in.
//! - **ECDSA P-256**: private key as PKCS#8 DER, public key as an uncompressed
//!   SEC1 point (65 bytes, leading `0x04`), signature as ASN.1 DER over
//!   SHA-256 — bit-compatible with `ring`'s `ECDSA_P256_SHA256_ASN1`, so a
//!   consumer can switch here without a wire change. Signing is RFC 6979
//!   deterministic; verifiers accept both deterministic and randomized
//!   signatures (the wire form is identical).
//!
//! Private keys cross the API only as [`SecretBuf`] (the secret-types rule (secrets cross APIs only as krypto types)).
//! Verification failure is [`Error::Auth`]; malformed keys/signatures are
//! [`Error::Format`].

use crate::error::Error;
use crate::secret::SecretBuf;

/// Length of a raw Ed25519 seed (the private key as the services store it).
pub const ED25519_SEED_LEN: usize = 32;
/// Length of a raw Ed25519 public key.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

fn ed25519_signing_key(seed: &SecretBuf) -> Result<ed25519_dalek::SigningKey, Error> {
    seed.expose(|b| {
        let arr: &[u8; ED25519_SEED_LEN] = b.try_into().map_err(|_| {
            Error::Format(format!(
                "an Ed25519 seed must be {ED25519_SEED_LEN} bytes, got {}",
                b.len()
            ))
        })?;
        Ok(ed25519_dalek::SigningKey::from_bytes(arr))
    })
}

/// New Ed25519 keypair: (seed, public key), both raw 32 bytes.
pub fn ed25519_keypair() -> Result<(SecretBuf, [u8; ED25519_PUBLIC_LEN]), Error> {
    let seed = SecretBuf::random(ED25519_SEED_LEN)?;
    let public = ed25519_public(&seed)?;
    Ok((seed, public))
}

/// The public key that belongs to an Ed25519 seed.
pub fn ed25519_public(seed: &SecretBuf) -> Result<[u8; ED25519_PUBLIC_LEN], Error> {
    let key = ed25519_signing_key(seed)?;
    Ok(key.verifying_key().to_bytes())
}

/// Sign `message` with a raw 32-byte Ed25519 seed.
pub fn ed25519_sign(seed: &SecretBuf, message: &[u8]) -> Result<[u8; ED25519_SIG_LEN], Error> {
    use ed25519_dalek::Signer;
    let key = ed25519_signing_key(seed)?;
    Ok(key.sign(message).to_bytes())
}

/// Verify an Ed25519 signature against a raw 32-byte public key.
/// `Error::Auth` when the signature does not hold; `Error::Format` when the
/// key or signature has the wrong shape.
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    use ed25519_dalek::Verifier;
    let pk: &[u8; ED25519_PUBLIC_LEN] = public.try_into().map_err(|_| {
        Error::Format(format!(
            "an Ed25519 public key must be {ED25519_PUBLIC_LEN} bytes, got {}",
            public.len()
        ))
    })?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(pk)
        .map_err(|_| Error::Format("invalid Ed25519 public key (not a curve point)".into()))?;
    let sig: &[u8; ED25519_SIG_LEN] = signature.try_into().map_err(|_| {
        Error::Format(format!(
            "an Ed25519 signature must be {ED25519_SIG_LEN} bytes, got {}",
            signature.len()
        ))
    })?;
    key.verify(message, &ed25519_dalek::Signature::from_bytes(sig))
        .map_err(|_| Error::Auth)
}

// --------------------------------------------------------------------------- //
// ECDSA P-256
// --------------------------------------------------------------------------- //

fn p256_signing_key(pkcs8: &SecretBuf) -> Result<p256::ecdsa::SigningKey, Error> {
    use p256::pkcs8::DecodePrivateKey;
    pkcs8.expose(|der| {
        p256::ecdsa::SigningKey::from_pkcs8_der(der)
            .map_err(|_| Error::Format("the private key is not ECDSA P-256 in PKCS#8 DER".into()))
    })
}

/// New ECDSA P-256 keypair: (private key as PKCS#8 DER, public key as an
/// uncompressed SEC1 point — 65 bytes, leading `0x04`).
pub fn ecdsa_p256_keypair() -> Result<(SecretBuf, Vec<u8>), Error> {
    use p256::pkcs8::EncodePrivateKey;
    // Draw scalars until one is a valid key (rejection sampling; a miss is
    // astronomically unlikely, the loop exists for correctness).
    let key = loop {
        let candidate = SecretBuf::random(32)?;
        let parsed = candidate.expose(|b| p256::ecdsa::SigningKey::from_slice(b).ok());
        if let Some(k) = parsed {
            break k;
        }
    };
    let doc = key
        .to_pkcs8_der()
        .map_err(|_| Error::Hardening("PKCS#8 encoding failed".into()))?;
    let private = SecretBuf::from_vec(doc.as_bytes().to_vec())?;
    let public = ecdsa_public_from_key(&key);
    Ok((private, public))
}

fn ecdsa_public_from_key(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(false) // false = uncompressed (65 bytes, 0x04 …)
        .as_bytes()
        .to_vec()
}

/// The uncompressed SEC1 public point (65 bytes) for a PKCS#8 private key.
pub fn ecdsa_p256_public(pkcs8: &SecretBuf) -> Result<Vec<u8>, Error> {
    Ok(ecdsa_public_from_key(&p256_signing_key(pkcs8)?))
}

/// Sign `message` (SHA-256, RFC 6979 deterministic) with a PKCS#8 private
/// key. Returns the signature as ASN.1 DER — the same wire form `ring`'s
/// `ECDSA_P256_SHA256_ASN1` verifies.
pub fn ecdsa_p256_sign(pkcs8: &SecretBuf, message: &[u8]) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::signature::Signer;
    let key = p256_signing_key(pkcs8)?;
    let sig: p256::ecdsa::Signature = key.sign(message);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Verify an ASN.1 DER ECDSA P-256 signature (over SHA-256) against a SEC1
/// public point (compressed or uncompressed). `Error::Auth` when the
/// signature does not hold; `Error::Format` on malformed key/signature.
pub fn ecdsa_p256_verify(public_sec1: &[u8], message: &[u8], sig_der: &[u8]) -> Result<(), Error> {
    use p256::ecdsa::signature::Verifier;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_sec1)
        .map_err(|_| Error::Format("invalid P-256 public key (not a SEC1 point)".into()))?;
    let sig = p256::ecdsa::Signature::from_der(sig_der)
        .map_err(|_| Error::Format("invalid ECDSA signature (not ASN.1 DER)".into()))?;
    key.verify(message, &sig).map_err(|_| Error::Auth)
}
