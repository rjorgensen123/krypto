//! The ONLY place in the crate with `unsafe` — thin wrappers around libc
//! (mlock/munlock/madvise/setrlimit/prctl). The rest of the crate is
//! `#![deny(unsafe_code)]`; this module allows unsafe locally.
#![allow(unsafe_code)]

use crate::error::Error;
#[cfg(not(miri))]
use std::io;

// Under Miri the libc syscalls below are unsupported and become no-ops: Miri
// runs no real process, so there is nothing to lock or exclude from dumps.
// The point of the Miri run is UB-detection in the crate's own memory and
// pointer handling — not in the kernel calls.

/// Lock `len` bytes from `ptr` in RAM (`mlock`). Fail-closed: failure → `Err`.
#[cfg(not(miri))]
pub(crate) fn mlock(ptr: *const u8, len: usize) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: `ptr` points to a valid allocation of at least `len` bytes, owned
    // by the caller (SecretBuf). mlock does not modify the contents.
    let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Hardening(format!(
            "mlock({len}) failed: {}",
            io::Error::last_os_error()
        )))
    }
}

/// Miri: no process memory to lock — see the module note above.
#[cfg(miri)]
pub(crate) fn mlock(_ptr: *const u8, _len: usize) -> Result<(), Error> {
    Ok(())
}

/// Unlock again (`munlock`). Best effort — errors are ignored (called from Drop).
#[cfg(not(miri))]
pub(crate) fn munlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: same allocation/length that was passed to `mlock`.
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Miri: nothing was locked.
#[cfg(miri)]
pub(crate) fn munlock(_ptr: *const u8, _len: usize) {}

/// Mark the pages as excluded from core dumps (`MADV_DONTDUMP`). Best effort.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn dontdump(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: valid allocation; madvise tolerates a non-page-aligned address
    // (the kernel rounds to whole pages).
    unsafe {
        let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
    }
}

/// No-op outside Linux (and under Miri — no pages, no dumps).
#[cfg(any(not(target_os = "linux"), miri))]
pub(crate) fn dontdump(_ptr: *const u8, _len: usize) {}

/// Disable core dumps for the process (`RLIMIT_CORE = 0`).
#[cfg(not(miri))]
pub(crate) fn disable_core_dumps() -> Result<(), Error> {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `&rlim` points to a valid `rlimit` on the stack.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Hardening(format!(
            "setrlimit(RLIMIT_CORE, 0) failed: {}",
            io::Error::last_os_error()
        )))
    }
}

/// Miri: no process, no core dumps.
#[cfg(miri)]
pub(crate) fn disable_core_dumps() -> Result<(), Error> {
    Ok(())
}

/// Make the process non-dumpable (`PR_SET_DUMPABLE = 0`). Linux.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn set_not_dumpable() -> Result<(), Error> {
    // SAFETY: prctl with PR_SET_DUMPABLE and the value 0 takes no pointer.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Hardening(format!(
            "prctl(PR_SET_DUMPABLE, 0) failed: {}",
            io::Error::last_os_error()
        )))
    }
}

/// No-op outside Linux (and under Miri).
#[cfg(any(not(target_os = "linux"), miri))]
pub(crate) fn set_not_dumpable() -> Result<(), Error> {
    Ok(())
}

/// Forbid the process — and its children — from ever gaining new privileges
/// (`prctl(PR_SET_NO_NEW_PRIVS, 1)`). Irreversible by design.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn no_new_privs() -> Result<(), Error> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes only integer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Hardening(format!(
            "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: {}",
            io::Error::last_os_error()
        )))
    }
}

/// Miri: no real process — nothing to forbid.
#[cfg(miri)]
pub(crate) fn no_new_privs() -> Result<(), Error> {
    Ok(())
}

/// Non-Linux: the mechanism does not exist here. Unlike the best-effort
/// baseline in `harden_process`, these opt-in calls promise a concrete
/// effect — claiming success without delivering it would be a lie, so:
/// fail closed.
#[cfg(all(not(target_os = "linux"), not(miri)))]
pub(crate) fn no_new_privs() -> Result<(), Error> {
    Err(Error::Hardening(
        "no_new_privs is only supported on Linux".into(),
    ))
}

/// Close every file descriptor above stderr (`close_range(3, MAX)`).
/// Needs Linux 5.9+; an unavailable syscall is a hard error, not a fallback.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn close_inherited_fds() -> Result<(), Error> {
    // SAFETY: close_range takes only integers, and closing descriptors
    // above stderr cannot invalidate any memory this crate holds.
    let rc = unsafe { libc::close_range(3, libc::c_uint::MAX, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Hardening(format!(
            "close_range(3, MAX) failed: {}",
            io::Error::last_os_error()
        )))
    }
}

/// Miri: no descriptor table to trim.
#[cfg(miri)]
pub(crate) fn close_inherited_fds() -> Result<(), Error> {
    Ok(())
}

/// Non-Linux: fail closed — see `no_new_privs` above.
#[cfg(all(not(target_os = "linux"), not(miri)))]
pub(crate) fn close_inherited_fds() -> Result<(), Error> {
    Err(Error::Hardening(
        "close_inherited_fds is only supported on Linux".into(),
    ))
}

/// `chroot` into `dir`, then `chdir("/")`. The caller (harden.rs) has
/// already verified that `dir` exists, is a directory and is empty.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn chroot_and_chdir(dir: &std::ffi::CStr) -> Result<(), Error> {
    // SAFETY: `dir` is a valid NUL-terminated path; chroot only reads it.
    let rc = unsafe { libc::chroot(dir.as_ptr()) };
    if rc != 0 {
        return Err(Error::Hardening(format!(
            "chroot failed: {}",
            io::Error::last_os_error()
        )));
    }
    // Without chdir("/") the working directory still points OUTSIDE the new
    // root — the classic chroot escape. A failure here leaves the process in
    // a state we refuse to paper over: hard error.
    let root = std::ffi::CString::new("/").expect("static string has no NUL");
    // SAFETY: valid NUL-terminated path.
    let rc = unsafe { libc::chdir(root.as_ptr()) };
    if rc != 0 {
        return Err(Error::Hardening(format!(
            "chdir(\"/\") after chroot failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Miri: no filesystem to drop.
#[cfg(miri)]
pub(crate) fn chroot_and_chdir(_dir: &std::ffi::CStr) -> Result<(), Error> {
    Ok(())
}

/// Non-Linux: fail closed — see `no_new_privs` above.
#[cfg(all(not(target_os = "linux"), not(miri)))]
pub(crate) fn chroot_and_chdir(_dir: &std::ffi::CStr) -> Result<(), Error> {
    Err(Error::Hardening(
        "drop_filesystem is only supported on Linux".into(),
    ))
}
