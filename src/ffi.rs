// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ONLY place in the crate with `unsafe` — thin wrappers around libc
//! (mmap/mprotect/mlock/madvise/munmap/setrlimit/prctl). The rest of the crate
//! is `#![deny(unsafe_code)]`; this module allows unsafe locally.
#![allow(unsafe_code)]

use crate::error::Error;
#[cfg(not(miri))]
use std::io;
use std::path::Path;

// Under Miri the libc syscalls below are unsupported: `LockedPages` falls back
// to an ordinary heap buffer and the process calls become no-ops. Miri runs no
// real process, so there is nothing to lock or exclude from dumps.
// The point of the Miri run is UB-detection in the crate's own memory and
// pointer handling — not in the kernel calls.

/// The memory of one secret, on pages of its own (0.7.2).
///
/// The mapping is one guard page, the data pages and one guard page. The guard
/// pages are `PROT_NONE`: an access that reaches one faults instead of reaching
/// other memory. The secret sits at the END of the data pages, so the first
/// byte past it is on the back guard page; before it lie the unused bytes of
/// its first page, then the front guard page. The data pages are locked in
/// RAM (`mlock`) and, on Linux, excluded from core dumps (`MADV_DONTDUMP`).
/// Every step is fail-closed: a failure → `Err`, and the secret is refused.
///
/// No page is shared with any other allocation, so dropping one secret can
/// never unlock another one's memory. Drop unmaps the whole mapping, which
/// also releases the lock. It does not wipe: the owner (`SecretBuf`) wipes
/// in its own `Drop`, which runs first.
#[cfg(not(miri))]
pub(crate) struct LockedPages {
    /// Start of the whole mapping (the first guard page).
    map: *mut u8,
    /// Length of the whole mapping, guard pages included; 0 when `len` is 0.
    map_len: usize,
    /// Start of the secret, at the end of the data pages.
    data: *mut u8,
    /// Bytes in use, from `data`.
    len: usize,
}

// SAFETY: `LockedPages` owns its mapping alone, like a `Box<[u8]>` owns its
// allocation, and has no interior mutability: `&self` gives only `&[u8]`, and
// writing needs `&mut self`. Sending or sharing it across threads is as safe as
// for `Box<[u8]>`. Without these, `SecretBuf` would silently stop being `Send`
// and `Sync`, which users rely on.
#[cfg(not(miri))]
unsafe impl Send for LockedPages {}
#[cfg(not(miri))]
unsafe impl Sync for LockedPages {}

#[cfg(not(miri))]
impl LockedPages {
    /// Map, guard, lock and mark `len` zeroed bytes. Fail-closed: failure → `Err`.
    pub(crate) fn new(len: usize) -> Result<Self, Error> {
        if len == 0 {
            let none = std::ptr::NonNull::<u8>::dangling().as_ptr();
            return Ok(LockedPages {
                map: none,
                map_len: 0,
                data: none,
                len: 0,
            });
        }
        let page = page_size()?;
        let too_large = || Error::Hardening(format!("a secret of {len} bytes is too large"));
        let data_len = len.checked_next_multiple_of(page).ok_or_else(too_large)?;
        let map_len = data_len.checked_add(2 * page).ok_or_else(too_large)?;

        // SAFETY: asks for a new private anonymous mapping and touches no
        // existing memory. The kernel hands it out zero-filled.
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(os_error(format_args!("mmap({map_len})")));
        }
        // The data pages start after the front guard. The secret sits at the
        // END of them, so the first byte past it is on the back guard page.
        let data_pages = map.cast::<u8>().wrapping_add(page);
        // From here on `pages` owns the mapping: an error below drops it, and
        // Drop unmaps it. Nothing has been written to it yet.
        let pages = LockedPages {
            map: map.cast(),
            map_len,
            data: data_pages.wrapping_add(data_len - len),
            len,
        };
        let back_guard = data_pages.wrapping_add(data_len);

        // SAFETY (all calls below): each range is whole pages inside the
        // mapping created above, which nothing else refers to.
        if unsafe { libc::mprotect(pages.map.cast(), page, libc::PROT_NONE) } != 0
            || unsafe { libc::mprotect(back_guard.cast(), page, libc::PROT_NONE) } != 0
        {
            return Err(os_error(format_args!("mprotect({page})")));
        }
        if unsafe { libc::mlock(data_pages.cast(), data_len) } != 0 {
            return Err(os_error(format_args!("mlock({data_len})")));
        }
        #[cfg(target_os = "linux")]
        {
            if unsafe { libc::madvise(data_pages.cast(), data_len, libc::MADV_DONTDUMP) } != 0 {
                return Err(os_error(format_args!("madvise(MADV_DONTDUMP, {data_len})")));
            }
        }
        Ok(pages)
    }

    /// The secret's bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `data` points to `len` readable bytes owned by `self` (or is
        // dangling with `len` 0), valid for as long as `&self` lives.
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }

    /// The secret's bytes, writable.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`, and `&mut self` makes the borrow exclusive.
        unsafe { std::slice::from_raw_parts_mut(self.data, self.len) }
    }
}

#[cfg(not(miri))]
impl Drop for LockedPages {
    fn drop(&mut self) {
        if self.map_len == 0 {
            return;
        }
        // SAFETY: the mapping created in `new`; nothing borrows it any more.
        // Unmapping also releases the lock. Best effort — errors are ignored
        // (Drop cannot fail).
        unsafe {
            let _ = libc::munmap(self.map.cast(), self.map_len);
        }
    }
}

/// The system page size.
#[cfg(not(miri))]
fn page_size() -> Result<usize, Error> {
    // SAFETY: sysconf takes only an integer.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(n)
        .ok()
        .filter(|p| p.is_power_of_two())
        .ok_or_else(|| Error::Hardening("sysconf(_SC_PAGESIZE) failed".into()))
}

/// `Error::Hardening` for a failed call, with the OS error.
#[cfg(not(miri))]
fn os_error(call: std::fmt::Arguments<'_>) -> Error {
    Error::Hardening(format!("{call} failed: {}", io::Error::last_os_error()))
}

/// Miri: an ordinary heap buffer — see the module note above.
#[cfg(miri)]
pub(crate) struct LockedPages {
    buf: Box<[u8]>,
}

#[cfg(miri)]
impl LockedPages {
    /// Miri: `len` zeroed bytes on the heap.
    pub(crate) fn new(len: usize) -> Result<Self, Error> {
        Ok(LockedPages {
            buf: vec![0u8; len].into_boxed_slice(),
        })
    }

    /// The secret's bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// The secret's bytes, writable.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

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

/// `chroot` into `dir`, on the directory as opened (0.7.3). The caller
/// (harden.rs) has already checked the path.
///
/// The process steps into the directory, checks that the directory it stands
/// in is empty, and makes it the root as the last step. So the process never
/// stands outside its own root, and the check and the chroot apply to the
/// same directory even if the path is swapped meanwhile. If a step fails, the
/// root is unchanged and the process steps back to where it stood; should
/// even that fail, the error says so.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn chroot_into(dir: &Path) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;

    // O_PATH opens a directory only to step into it; it needs no read access.
    let open = |path: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(path)
    };
    // Where the process stands now, to step back to. Once the root changes it
    // points outside the new root, so it must not outlive this call: it is
    // closed when this returns, and never inherited (O_CLOEXEC).
    let here = open(Path::new("."))?;
    let target = open(dir)?;
    fchdir(&target)
        .map_err(|e| Error::Hardening(format!("stepping into {} failed: {e}", dir.display())))?;
    if let Err(why) = chroot_here(dir) {
        return Err(Error::Hardening(match fchdir(&here) {
            Ok(()) => why,
            Err(e) => format!("{why}; stepping back failed too: {e}"),
        }));
    }
    Ok(())
}

/// Check that the directory the process stands in is empty, then make it the
/// root.
#[cfg(all(target_os = "linux", not(miri)))]
fn chroot_here(dir: &Path) -> Result<(), String> {
    let mut entries = std::fs::read_dir(".")
        .map_err(|e| format!("reading chroot target {} failed: {e}", dir.display()))?;
    if entries.next().is_some() {
        return Err(format!("chroot target {} is not empty", dir.display()));
    }
    // SAFETY: a static NUL-terminated path; chroot only reads it.
    if unsafe { libc::chroot(c".".as_ptr()) } != 0 {
        return Err(format!("chroot failed: {}", io::Error::last_os_error()));
    }
    Ok(())
}

/// Make the directory open on `dir` the working directory.
#[cfg(all(target_os = "linux", not(miri)))]
fn fchdir(dir: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    // SAFETY: fchdir takes only a descriptor, which `dir` keeps open.
    if unsafe { libc::fchdir(dir.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Miri: no filesystem to drop.
#[cfg(miri)]
pub(crate) fn chroot_into(_dir: &Path) -> Result<(), Error> {
    Ok(())
}

/// Non-Linux: fail closed — see `no_new_privs` above.
#[cfg(all(not(target_os = "linux"), not(miri)))]
pub(crate) fn chroot_into(_dir: &Path) -> Result<(), Error> {
    Err(Error::Hardening(
        "drop_filesystem is only supported on Linux".into(),
    ))
}
