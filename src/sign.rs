// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signatures: Ed25519 (raw keys) and ECDSA P-256 (PKCS#8 / SEC1 / DER).
//!
//! Exists so no consumer rolls its own signature layer — nettls went straight
//! to `ring` for exactly this. The forms are chosen to
//! match the forms already in common use:
//!
//! - **Ed25519**: raw 32-byte seed and raw 32-byte public key, 64-byte
//!   signature — the form public keys are usually distributed in.
//!   [`ed25519_verify`] is strict and refuses weak (small-order) keys;
//!   [`ed25519_verify_relaxed`] accepts them, for a caller that must (0.8.2).
//! - **ECDSA P-256**: private key as PKCS#8 DER, public key as an uncompressed
//!   SEC1 point (65 bytes, leading `0x04`), signature as ASN.1 DER over
//!   SHA-256 — bit-compatible with `ring`'s `ECDSA_P256_SHA256_ASN1`, so a
//!   consumer can switch here without a wire change. Signing is RFC 6979
//!   deterministic; verifiers accept both deterministic and randomized
//!   signatures (the wire form is identical).
//!
//! Private keys cross the API only as [`SecretBuf`]: secrets cross APIs only as krypto types.
//! Verification failure is [`Error::Auth`]; malformed keys/signatures are
//! [`Error::Format`].

use crate::error::Error;
use crate::secret::SecretBuf;
use crate::util::check_data_len;

/// Length of a raw Ed25519 seed (the private key in its stored form).
pub const ED25519_SEED_LEN: usize = 32;
/// Length of a raw Ed25519 public key.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;
/// The longest P-256 public key [`ecdsa_p256_verify`] takes: an uncompressed
/// SEC1 point, 65 bytes (0.9.0).
pub const MAX_ECDSA_P256_PUBLIC_BYTES: usize = 65;
/// The longest ECDSA P-256 signature [`ecdsa_p256_verify`] takes: the largest
/// ASN.1 DER form, 72 bytes (0.9.0).
pub const MAX_ECDSA_P256_SIG_BYTES: usize = 72;
/// The longest P-256 private key (PKCS#8 DER) [`ecdsa_p256_public`] and
/// [`ecdsa_p256_sign`] take, in bytes (0.9.0).
pub const MAX_ECDSA_P256_PKCS8_BYTES: usize = 512;

/// Refuses `len` above `max` with `Error::Format` (0.9.0). `what` names the
/// input; the message carries only the lengths.
fn check_len(what: &str, len: usize, max: usize) -> Result<(), Error> {
    if len > max {
        return Err(Error::Format(format!("{what} is {len} bytes — max {max}")));
    }
    Ok(())
}

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
///
/// `message` is at most [`crate::MAX_DATA_BYTES`]; more is `Error::Format`,
/// refused before anything else (0.9.0).
pub fn ed25519_sign(seed: &SecretBuf, message: &[u8]) -> Result<[u8; ED25519_SIG_LEN], Error> {
    use ed25519_dalek::Signer;
    check_data_len("message", message.len())?;
    let key = ed25519_signing_key(seed)?;
    Ok(key.sign(message).to_bytes())
}

fn ed25519_verifying_key(public: &[u8]) -> Result<ed25519_dalek::VerifyingKey, Error> {
    let pk: &[u8; ED25519_PUBLIC_LEN] = public.try_into().map_err(|_| {
        Error::Format(format!(
            "an Ed25519 public key must be {ED25519_PUBLIC_LEN} bytes, got {}",
            public.len()
        ))
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(pk)
        .map_err(|_| Error::Format("invalid Ed25519 public key (not a curve point)".into()))
}

fn ed25519_signature(signature: &[u8]) -> Result<ed25519_dalek::Signature, Error> {
    let sig: &[u8; ED25519_SIG_LEN] = signature.try_into().map_err(|_| {
        Error::Format(format!(
            "an Ed25519 signature must be {ED25519_SIG_LEN} bytes, got {}",
            signature.len()
        ))
    })?;
    Ok(ed25519_dalek::Signature::from_bytes(sig))
}

/// Verify an Ed25519 signature against a raw 32-byte public key, strictly
/// (0.8.2). A public key of small order (a weak key, for which anyone can make
/// signatures), an R of small order in the signature, and a public key that is
/// not in its one canonical 32-byte encoding are refused, so `Ok` means the
/// signature was made with the private key that belongs to that public key.
///
/// `Error::Auth` when the signature does not hold, or the key or R is of small
/// order; `Error::Format` when the key or signature has the wrong shape, or
/// the key is not canonically encoded.
///
/// `message` is at most [`crate::MAX_DATA_BYTES`]; more is `Error::Format`,
/// refused before anything else (0.9.0).
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    check_data_len("message", message.len())?;
    let key = ed25519_verifying_key(public)?;
    // The same point can have more than one 32-byte encoding; only the one
    // the point encodes back to is accepted.
    if key.to_edwards().compress().as_bytes()[..] != *public {
        return Err(Error::Format(
            "invalid Ed25519 public key (not the canonical encoding of its point)".into(),
        ));
    }
    let sig = ed25519_signature(signature)?;
    key.verify_strict(message, &sig).map_err(|_| Error::Auth)
}

/// Verify an Ed25519 signature against a raw 32-byte public key, relaxed
/// (0.8.2). It only checks that the signature equation holds: weak
/// (small-order) keys, an R of small order and non-canonical key encodings
/// are not refused, and for a weak key anyone can make signatures without a
/// private key.
///
/// Use it only where such keys must be accepted, never to check who signed
/// with a public key that came from someone else; that is
/// [`ed25519_verify`]. `Error::Auth` when the signature does not hold;
/// `Error::Format` when the key or signature has the wrong shape.
///
/// `message` is at most [`crate::MAX_DATA_BYTES`]; more is `Error::Format`,
/// refused before anything else (0.9.0).
pub fn ed25519_verify_relaxed(
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use ed25519_dalek::Verifier;
    check_data_len("message", message.len())?;
    let key = ed25519_verifying_key(public)?;
    let sig = ed25519_signature(signature)?;
    key.verify(message, &sig).map_err(|_| Error::Auth)
}

// --------------------------------------------------------------------------- //
// ECDSA P-256
// --------------------------------------------------------------------------- //

/// Parses a PKCS#8 P-256 private key. One longer than
/// [`MAX_ECDSA_P256_PKCS8_BYTES`] is `Error::Format`, before the parser is
/// called (0.9.0).
fn p256_signing_key(pkcs8: &SecretBuf) -> Result<p256::ecdsa::SigningKey, Error> {
    use p256::pkcs8::DecodePrivateKey;
    check_len("P-256 private key", pkcs8.len(), MAX_ECDSA_P256_PKCS8_BYTES)?;
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
        .to_sec1_point(false) // false = uncompressed (65 bytes, 0x04 …)
        .as_bytes()
        .to_vec()
}

/// The uncompressed SEC1 public point (65 bytes) for a PKCS#8 private key.
///
/// `pkcs8` is at most [`MAX_ECDSA_P256_PKCS8_BYTES`]; a longer one is
/// `Error::Format`, refused before it is parsed (0.9.0).
pub fn ecdsa_p256_public(pkcs8: &SecretBuf) -> Result<Vec<u8>, Error> {
    Ok(ecdsa_public_from_key(&p256_signing_key(pkcs8)?))
}

/// Sign `message` (SHA-256, RFC 6979 deterministic) with a PKCS#8 private
/// key. Returns the signature as ASN.1 DER — the same wire form `ring`'s
/// `ECDSA_P256_SHA256_ASN1` verifies.
///
/// `message` is at most [`crate::MAX_DATA_BYTES`] and `pkcs8` at most
/// [`MAX_ECDSA_P256_PKCS8_BYTES`]; a longer one is `Error::Format`, checked in
/// that order, before the key is parsed (0.9.0).
pub fn ecdsa_p256_sign(pkcs8: &SecretBuf, message: &[u8]) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::signature::Signer;
    check_data_len("message", message.len())?;
    let key = p256_signing_key(pkcs8)?;
    let sig: p256::ecdsa::Signature = key.sign(message);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Verify an ASN.1 DER ECDSA P-256 signature (over SHA-256) against a SEC1
/// public point (compressed or uncompressed). `Error::Auth` when the
/// signature does not hold; `Error::Format` on malformed key/signature.
///
/// `message` is at most [`crate::MAX_DATA_BYTES`], `public_sec1` at most
/// [`MAX_ECDSA_P256_PUBLIC_BYTES`] and `sig_der` at most
/// [`MAX_ECDSA_P256_SIG_BYTES`]; a longer one is `Error::Format`, checked in
/// that order, before the key or the signature is parsed (0.9.0).
pub fn ecdsa_p256_verify(public_sec1: &[u8], message: &[u8], sig_der: &[u8]) -> Result<(), Error> {
    use p256::ecdsa::signature::Verifier;
    check_data_len("message", message.len())?;
    check_len(
        "P-256 public key",
        public_sec1.len(),
        MAX_ECDSA_P256_PUBLIC_BYTES,
    )?;
    check_len("ECDSA signature", sig_der.len(), MAX_ECDSA_P256_SIG_BYTES)?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_sec1)
        .map_err(|_| Error::Format("invalid P-256 public key (not a SEC1 point)".into()))?;
    let sig = p256::ecdsa::Signature::from_der(sig_der)
        .map_err(|_| Error::Format("invalid ECDSA signature (not ASN.1 DER)".into()))?;
    key.verify(message, &sig).map_err(|_| Error::Auth)
}
