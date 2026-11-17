// SPDX-License-Identifier: MIT OR Apache-2.0
//! The crate's error type.

use std::fmt;

/// Errors from `krypto`.
///
/// `#[non_exhaustive]` so new variants can be added without a breaking change
/// (`Format`/`Auth` arrived in 0.2, `KeyNotFound` in 0.3, `WrongKey` in 0.5,
/// `Rollback` in 0.9). No variant carries key material or plaintext.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// I/O error: a file or directory could not be opened, read or written.
    /// Also a store file that an open anchored above counter 0 did not find,
    /// since such an open does not create one.
    Io(std::io::Error),
    /// A protection step could not be carried out, or the environment failed:
    /// locked or protected memory, randomness, process hardening, or an
    /// internal step. Treated fail-closed. It is never a verdict on whether
    /// data is genuine. One case comes from a file: a `SecretStore` write is
    /// refused because the store's counter is at its maximum, and the store
    /// must be rotated before it can be written again.
    Hardening(String),
    /// The input has the wrong shape: not a krypto blob, or a malformed key,
    /// signature, PHC string, encoding or parameter, such as an empty `info`
    /// (0.7.3). Not a krypto blob means shorter than its 4-byte magic, or not
    /// starting with `FAFN` (0.9.0; before that, shorter than the 54-byte
    /// header, or not starting with `FAFN`). For a `SecretStore`: not a store
    /// file, a store version krypto does not know or other than the one the
    /// open names, or an invalid entry structure, which in a v2 file whose
    /// container MAC holds means it was written that way.
    Format(String),
    /// Authentication failed: a blob, signature or password that does not hold —
    /// tampering, or the wrong key or password. Any change to a blob past its
    /// `FAFN` magic is `Auth`, a version or algorithm krypto does not know
    /// included (0.7.3), a header cut short included (0.9.0), and never a
    /// mis-decrypt (the key-id swap test). At the open of a v2 store file it
    /// means the file is not what was written, whatever the cause: it is cut
    /// short of its header, or the master key fits and something else in the
    /// file was changed, added or removed.
    Auth,
    /// Lookup in a SecretStore found no value under the key name.
    KeyNotFound,
    /// The key offered does not fit: a blob sealed under a different key
    /// generation, or a v2 store file whose `key_check` does not fit the
    /// master key.
    ///
    /// For a blob this is a routing outcome, not a security event: the caller
    /// should locate the right key (see `blob_key_id`), whereas [`Error::Auth`]
    /// is tampering or a wrong key and SHOULD be alarmed on. Added in 0.5.0 so
    /// an old-generation blob no longer masquerades as tampering (the
    /// contract is `docs/API.md`, section `error`). Since 0.7.3 no blob
    /// function of the library returns it — a `SecretStore` holds one
    /// generation — it is the answer for a caller that holds several and
    /// routes between them, as `krypto-cli open` does.
    ///
    /// The `SecretStore` opens return it for a v2 file whose master key does
    /// not fit. A changed salt or `key_check` gives the same answer and cannot
    /// be told from a wrong key, so a caller that knows its key is the right
    /// one treats it as a changed file.
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
                "the key does not fit (a blob under another key generation, or a store file \
                 whose key check does not match)"
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
