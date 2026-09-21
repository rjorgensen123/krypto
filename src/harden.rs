//! Process hardening — every call is fail-closed, and each is a separate,
//! deliberate choice, because they carry different costs:
//!
//! 1. [`harden_process`] — always safe; call it first in `main`.
//! 2. [`no_new_privs`] — always safe; call it right after.
//! 3. [`close_inherited_fds`] — also closes descriptors inherited on
//!    purpose (socket activation), so the service must choose it.
//! 4. [`drop_filesystem`] — irreversible and needs privileges; call it
//!    AFTER reading key material, before serving traffic.

use std::path::Path;

use crate::error::Error;
use crate::ffi;

/// Harden the process: disable core dumps (`RLIMIT_CORE = 0`) and make the
/// process non-dumpable (`PR_SET_DUMPABLE = 0` on Linux).
///
/// Should be called first in a consumer's `main`. Idempotent (safe to call
/// multiple times). Fail-closed: returns `Err` if either operation fails.
pub fn harden_process() -> Result<(), Error> {
    ffi::disable_core_dumps()?;
    ffi::set_not_dumpable()?;
    Ok(())
}

/// Forbid the process — and every child it ever spawns — from gaining
/// privileges it does not already have (`prctl(PR_SET_NO_NEW_PRIVS, 1)`).
///
/// This blocks the whole class of setuid/setcap escalation tricks: after
/// the call, `execve` can never grant more than the process already holds.
/// Irreversible by design, inherited by children, and without downside for
/// a service that never intends to escalate — call it early, right after
/// [`harden_process`]. Idempotent. Fail-closed. Linux only.
pub fn no_new_privs() -> Result<(), Error> {
    ffi::no_new_privs()
}

/// Close every inherited file descriptor above stderr, in one call
/// (`close_range(3, MAX)` — no `/proc` needed).
///
/// A descriptor leaked from the parent — a log file, a socket, someone
/// else's pipe — is both an information leak and an attack surface.
///
/// Two things to know before calling it:
///
/// - It also closes descriptors the service inherited *on purpose* (e.g.
///   systemd socket activation). That is why this is a separate call and
///   not part of [`harden_process`] — the service decides.
/// - Call it early, before the service opens its own files and sockets.
///
/// Requires Linux 5.9+; on an older kernel the call fails — fail-closed,
/// like everything in this module.
pub fn close_inherited_fds() -> Result<(), Error> {
    ffi::close_inherited_fds()
}

/// Make the filesystem disappear for this process: `chroot` into `dir` —
/// which MUST be an empty directory — followed by `chdir("/")`.
///
/// After this call the process cannot open key files, configuration or
/// anything else on disk, because kernel-wise they no longer exist: an
/// attacker with a foothold in the running process finds no key file to
/// read. krypto itself needs nothing from the filesystem afterwards —
/// randomness comes from the `getrandom` syscall (not `/dev/urandom`), and
/// AEAD, KDF, signing and password hashing touch no files.
///
/// The rules, enforced or fail-closed:
///
/// - `dir` must exist, be a directory and be EMPTY — verified before the
///   chroot. Anything else is a hard error.
/// - The call is irreversible. Do it AFTER reading key material.
/// - It requires privileges (root or `CAP_SYS_CHROOT`). Ideally services
///   run without them — but when they are available, use them to protect
///   the process. Without them the call fails, and the caller decides
///   whether that should have been possible.
pub fn drop_filesystem(dir: impl AsRef<Path>) -> Result<(), Error> {
    let dir = dir.as_ref();
    let meta = std::fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(Error::Hardening(format!(
            "chroot target {} is not a directory",
            dir.display()
        )));
    }
    if std::fs::read_dir(dir)?.next().is_some() {
        return Err(Error::Hardening(format!(
            "chroot target {} is not empty",
            dir.display()
        )));
    }
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::Hardening("chroot target path contains NUL".into()))?;
    ffi::chroot_and_chdir(&c)
}
