// SPDX-License-Identifier: MIT OR Apache-2.0
//! The secret types [`SecretBuf`] and [`SecretString`].

use std::fmt;

use zeroize::Zeroize;

use crate::error::Error;
use crate::ffi;

/// Owned, `mlock`'ed byte buffer for secrets. Zeroized on drop.
///
/// - No `Clone`, no `Serialize`.
/// - `Debug`/`Display` only ever show `SecretBuf([REDACTED], len=N)`.
/// - Plaintext is only reachable through [`SecretBuf::expose`].
/// - Each buffer has whole memory pages of its own, locked in RAM and, on
///   Linux, kept out of core dumps (0.7.2). It therefore counts at least one
///   page (usually 4 KiB) against `RLIMIT_MEMLOCK`.
pub struct SecretBuf {
    pages: ffi::LockedPages,
}

impl SecretBuf {
    /// Takes ownership of `v`, copies it into locked memory and zeroizes the source.
    pub fn from_vec(mut v: Vec<u8>) -> Result<Self, Error> {
        // The source is wiped on EVERY path, the error path included. An
        // `mlock` failure is precisely the moment a secret would otherwise be
        // left behind in the heap — and a container's `RLIMIT_MEMLOCK` makes
        // that reachable, not hypothetical. `?` here would have skipped the wipe.
        //
        // The buffer becomes a `SecretBuf` before it is filled, the same shape
        // as `random`: `Drop` (zeroize + unmap) owns it from the first instant.
        let out = ffi::LockedPages::new(v.len()).map(|pages| {
            let mut s = SecretBuf { pages };
            s.pages.as_mut_slice().copy_from_slice(&v);
            s
        });
        v.zeroize();
        out
    }

    /// A buffer of `len` bytes in locked memory, filled in place by `fill`
    /// (0.7.2). The bytes never exist outside locked memory, and if `fill`
    /// fails or panics, `Drop` wipes what it wrote.
    pub(crate) fn fill_with(
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let mut s = SecretBuf {
            pages: ffi::LockedPages::new(len)?,
        };
        fill(s.pages.as_mut_slice())?;
        Ok(s)
    }

    /// New buffer of `len` bytes filled from the OS CSPRNG.
    pub fn random(len: usize) -> Result<Self, Error> {
        // Construct the `SecretBuf` BEFORE filling it, so a getrandom failure
        // drops a type with `Drop` (zeroize + unmap) — not bare pages that
        // would be unmapped unwiped.
        let mut s = SecretBuf {
            pages: ffi::LockedPages::new(len)?,
        };
        getrandom::fill(s.pages.as_mut_slice())
            .map_err(|e| Error::Hardening(format!("getrandom failed: {e}")))?;
        Ok(s)
    }

    /// Number of bytes.
    pub fn len(&self) -> usize {
        self.pages.as_slice().len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.pages.as_slice().is_empty()
    }

    /// Run `f` with the plaintext bytes. The reference cannot escape the scope (lifetime).
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(self.pages.as_slice())
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // Wipe first; dropping `pages` afterwards unmaps them, which also
        // releases the lock.
        self.pages.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf([REDACTED], len={})", self.len())
    }
}

impl fmt::Display for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf([REDACTED], len={})", self.len())
    }
}

/// Like [`SecretBuf`], but guaranteed valid UTF-8 (built from a `String`).
pub struct SecretString {
    inner: SecretBuf,
}

impl SecretString {
    /// Takes ownership of `s`, stores it in locked memory and zeroizes the source.
    pub fn from_string(s: String) -> Result<Self, Error> {
        // into_bytes() reuses the String allocation; from_vec zeroizes it
        // after copying into locked memory.
        let inner = SecretBuf::from_vec(s.into_bytes())?;
        Ok(SecretString { inner })
    }

    /// Number of bytes (not number of characters).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Run `f` with the plaintext string. The reference cannot escape the scope.
    pub fn expose_str<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        self.inner.expose(|b| {
            // Invariant: built from a valid String and never mutated.
            let s = std::str::from_utf8(b).expect("SecretString invariant: valid UTF-8");
            f(s)
        })
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED], len={})", self.inner.len())
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED], len={})", self.inner.len())
    }
}
