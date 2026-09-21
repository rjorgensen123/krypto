//! The crate's error type.

use std::fmt;

/// Errors from `krypto`.
///
/// `#[non_exhaustive]` so new variants can be added without a breaking change
/// (`Format`/`Auth` arrived in 0.2, `KeyNotFound` in 0.3, `WrongKey` in 0.5).
/// No variant carries key material or plaintext.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// I/O error.
    Io(std::io::Error),
    /// Hardening/locking failed (mlock, rlimit or prctl). Treated fail-closed.
    Hardening(String),
    /// Invalid blob format (magic, version, unknown/unsupported alg_id, truncation).
    Format(String),
    /// Authentication failed — header or ciphertext tampering, or the wrong key.
    /// (Covers the key-id swap test: a manipulated header yields Auth, never a mis-decrypt.)
    Auth,
    /// Lookup in a SecretStore found no value under the key name.
    KeyNotFound,
    /// The blob was sealed under a different key generation than the one offered.
    ///
    /// This is a routing outcome, not a security event: the caller should locate
    /// the right key (see `blob_key_id`), whereas [`Error::Auth`] is tampering or
    /// a wrong key and SHOULD be alarmed on. Added in 0.5.0 so an old-generation
    /// blob no longer masquerades as tampering (finding N5; contract: API-krypto-v0.6 §errors).
    WrongKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Hardening(m) => write!(f, "hardening error: {m}"),
            Error::Format(m) => write!(f, "format error: {m}"),
            Error::Auth => write!(f, "authentication failure (tampering or wrong key)"),
            Error::KeyNotFound => write!(f, "key name not found in store"),
            Error::WrongKey => write!(
                f,
                "blob was sealed under a different key generation (not tampering)"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
