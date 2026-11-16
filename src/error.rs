// SPDX-License-Identifier: MIT OR Apache-2.0
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
    /// A protection step could not be carried out, or the environment failed:
    /// locked or protected memory, randomness, process hardening, or an internal
    /// step no input can cause. Never a verdict on the data. Treated fail-closed.
    Hardening(String),
    /// The input has the wrong shape: not a krypto blob (shorter than its
    /// 4-byte magic, or not starting with `FAFN`), or a malformed key,
    /// signature, PHC string, encoding or parameter, such as an empty `info`
    /// (0.7.3).
    Format(String),
    /// Authentication failed: a blob, signature or password that does not hold —
    /// tampering, or the wrong key or password. Any change to a blob past its
    /// `FAFN` magic is `Auth`, a version or algorithm krypto does not know
    /// included (0.7.3), a header cut short included (0.9.0), and never a
    /// mis-decrypt (the key-id swap test).
    Auth,
    /// Lookup in a SecretStore found no value under the key name.
    KeyNotFound,
    /// The blob was sealed under a different key generation than the one offered.
    ///
    /// This is a routing outcome, not a security event: the caller should locate
    /// the right key (see `blob_key_id`), whereas [`Error::Auth`] is tampering or
    /// a wrong key and SHOULD be alarmed on. Added in 0.5.0 so an old-generation
    /// blob no longer masquerades as tampering (finding N5; contract: API-krypto-v0.6 §errors).
    /// Since 0.7.3 no library function returns it — a `SecretStore` holds one
    /// generation — it is the answer for a caller that holds several and routes
    /// between them, as `krypto-cli open` does.
    WrongKey,
    /// An anchored open of a store file found an older copy than the caller
    /// has seen: the file's v2 `counter` is below the minimum the caller
    /// supplied (0.9.0). krypto is stateless, so the anchor lives outside the
    /// file; the counter itself is covered by the store's container MAC and
    /// cannot be lowered without breaking it.
    Rollback {
        /// The counter in the store file that was opened.
        file_counter: u64,
        /// The minimum counter the caller anchored to.
        min_counter: u64,
    },
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
            Error::Rollback {
                file_counter,
                min_counter,
            } => write!(
                f,
                "rollback detected: the store file's counter is {file_counter}, below the \
                 required minimum {min_counter} — the file is an older copy than the caller \
                 has seen"
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
