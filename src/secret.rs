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
pub struct SecretBuf {
    buf: Box<[u8]>,
}

impl SecretBuf {
    /// Allocate + `mlock` a zeroed buffer of `len` bytes. Fail-closed on mlock.
    fn locked_zeroed(len: usize) -> Result<Box<[u8]>, Error> {
        let buf = vec![0u8; len].into_boxed_slice();
        ffi::mlock(buf.as_ptr(), buf.len())?;
        ffi::dontdump(buf.as_ptr(), buf.len());
        Ok(buf)
    }

    /// Takes ownership of `v`, copies it into locked memory and zeroizes the source.
    pub fn from_vec(mut v: Vec<u8>) -> Result<Self, Error> {
        // The source is wiped on EVERY path, the error path included. An
        // `mlock` failure is precisely the moment a secret would otherwise be
        // left behind in the heap — and a container's `RLIMIT_MEMLOCK` makes
        // that reachable, not hypothetical. `?` here would have skipped the wipe.
        //
        // The buffer becomes a `SecretBuf` before it is filled, the same shape
        // as `random`: `Drop` (munlock + zeroize) owns it from the first instant.
        let out = Self::locked_zeroed(v.len()).map(|buf| {
            let mut s = SecretBuf { buf };
            s.buf.copy_from_slice(&v);
            s
        });
        v.zeroize();
        out
    }

    /// New buffer of `len` bytes filled from the OS CSPRNG.
    pub fn random(len: usize) -> Result<Self, Error> {
        // Construct the `SecretBuf` BEFORE filling it, so a getrandom failure
        // drops a type with `Drop` (munlock + zeroize) — not a raw `Box<[u8]>`
        // that would leak the mlock until process exit.
        let mut s = SecretBuf {
            buf: Self::locked_zeroed(len)?,
        };
        getrandom::getrandom(&mut s.buf[..])
            .map_err(|e| Error::Hardening(format!("getrandom failed: {e}")))?;
        Ok(s)
    }

    /// Number of bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Run `f` with the plaintext bytes. The reference cannot escape the scope (lifetime).
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.buf)
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.buf.zeroize();
        ffi::munlock(self.buf.as_ptr(), self.buf.len());
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf([REDACTED], len={})", self.buf.len())
    }
}

impl fmt::Display for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf([REDACTED], len={})", self.buf.len())
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
