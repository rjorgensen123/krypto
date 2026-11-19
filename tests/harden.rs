// SPDX-License-Identifier: MIT OR Apache-2.0
//! Process hardening tests.
//!
//! The dangerous calls run in a FORKED CHILD so that a success (e.g. the
//! suite running as root in CI) cannot damage the test binary itself. The
//! fork tests are compiled out under Miri — fork and the syscalls are
//! unsupported there, and the ffi layer is a no-op anyway.

#[test]
fn harden_turns_off_core_dumps_and_is_idempotent() {
    // Must succeed without special privileges (lowers limits / sets dumpable).
    krypto::harden_process().expect("harden_process should succeed");
    // Idempotent: safe to call multiple times.
    krypto::harden_process().expect("harden_process should be idempotent");
    // (0.8.0) And the kernel says it took: no core dumps, and not dumpable.
    #[cfg(not(miri))]
    {
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `&mut rlim` points to a valid `rlimit` on the stack.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) }, 0);
        assert_eq!((rlim.rlim_cur, rlim.rlim_max), (0, 0), "core dumps are on");
        // SAFETY: PR_GET_DUMPABLE takes no pointer; the unused arguments are 0.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0, "the process is still dumpable");
    }
}

#[test]
fn no_new_privs_is_set_and_idempotent() {
    // Needs no privileges, and setting the bit twice is fine. Affects only
    // privilege-gaining execve, which the test process never does.
    krypto::no_new_privs().expect("no_new_privs should succeed");
    krypto::no_new_privs().expect("no_new_privs should be idempotent");
    // (0.8.0) And the kernel says the bit is set.
    #[cfg(not(miri))]
    {
        // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer; the kernel wants the
        // unused arguments 0, or it fails with EINVAL.
        let set = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        assert_eq!(set, 1, "no_new_privs is not set");
    }
}

#[cfg(not(miri))]
mod forked {
    use std::os::unix::io::AsRawFd;

    /// Run `f` in a forked child and return its exit code. The child sticks
    /// to syscalls and `_exit` on the success paths; glibc's atfork handlers
    /// make the error-path allocations safe too.
    fn in_child(f: impl FnOnce() -> i32) -> i32 {
        // SAFETY: fork(); the child never returns, only _exits.
        unsafe {
            match libc::fork() {
                -1 => panic!("fork failed"),
                0 => libc::_exit(f()),
                pid => {
                    let mut status = 0;
                    assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
                    assert!(libc::WIFEXITED(status), "child did not exit normally");
                    libc::WEXITSTATUS(status)
                }
            }
        }
    }

    /// What `/proc/self/fd` shows above stderr: for each descriptor, whether
    /// it is open on `/dev/urandom`, and the device and inode of what it is
    /// open on. `None` if the table cannot be read.
    fn open_descriptors() -> Option<Vec<(bool, (u64, u64))>> {
        use std::os::unix::fs::MetadataExt;
        let mut open = Vec::new();
        for entry in std::fs::read_dir("/proc/self/fd").ok()? {
            let entry = entry.ok()?;
            let fd: i32 = entry.file_name().to_str()?.parse().ok()?;
            if fd > 2 {
                let meta = std::fs::metadata(entry.path()).ok()?;
                let urandom = std::fs::read_link(entry.path())
                    .is_ok_and(|t| t == std::path::Path::new("/dev/urandom"));
                open.push((urandom, (meta.dev(), meta.ino())));
            }
        }
        Some(open)
    }

    #[test]
    fn close_inherited_fds_closes_above_stderr() {
        use std::os::unix::fs::MetadataExt;
        // Open the fd in the PARENT so the child does not allocate before
        // the syscall; the fork gives the child its own copy of the table.
        let f = std::fs::File::open("/etc/os-release")
            .or_else(|_| std::fs::File::open("/etc/hostname"))
            .expect("no readable /etc file for the test");
        let fd = f.as_raw_fd();
        let meta = f.metadata().expect("metadata of the inherited file");
        let file = (meta.dev(), meta.ino());
        let code = in_child(|| {
            if krypto::close_inherited_fds().is_err() {
                return 3;
            }
            // The file is recognised by what it is, not by its number: where
            // the `getrandom` crate reads `/dev/urandom` and had not opened
            // it yet, the call's test of the random source opens it, under
            // the lowest free number, which can be the file's old one.
            let Some(open) = open_descriptors() else {
                return 5;
            };
            if open.iter().any(|(_, what)| *what == file) {
                return 4;
            }
            // Without `/dev/urandom` open, the number itself is closed too.
            // SAFETY: fcntl on a plain integer descriptor.
            let gone = unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1;
            if gone || open.iter().any(|(urandom, _)| *urandom) {
                0
            } else {
                4
            }
        });
        assert_eq!(
            code, 0,
            "3 = call failed, 4 = the fd survived, 5 = /proc/self/fd unreadable"
        );
        // The parent's copy is untouched by the child's close_range.
        drop(f);
    }

    #[test]
    fn drop_filesystem_validates_and_fails_closed() {
        // Nonexistent path → hard error, before any chroot is attempted.
        assert!(krypto::drop_filesystem("/definitely/not/here").is_err());

        // Non-empty directory → hard error, still before any chroot.
        assert!(krypto::drop_filesystem("/etc").is_err());

        // Empty directory: attempt the real thing IN A CHILD. As root the
        // chroot succeeds (and only the child is jailed) with the child inside
        // its new, empty root; unprivileged it must fail closed with
        // Error::Hardening (EPERM) and leave the child where it stood.
        let dir = std::env::temp_dir().join(format!("krypto-chroot-test-{}", std::process::id()));
        std::fs::create_dir(&dir).expect("mkdir for chroot target");
        let euid_is_root = unsafe { libc::geteuid() } == 0;
        let target = dir.clone();
        let code = in_child(move || {
            let before = std::env::current_dir().ok();
            match krypto::drop_filesystem(&target) {
                Ok(()) => {
                    let inside = std::env::current_dir().is_ok_and(|d| d.as_os_str() == "/");
                    if inside && !std::path::Path::new("/etc").exists() {
                        0
                    } else {
                        5
                    }
                }
                Err(krypto::Error::Hardening(_)) => {
                    if std::env::current_dir().ok() == before {
                        2
                    } else {
                        6
                    }
                }
                Err(_) => 3,
            }
        });
        std::fs::remove_dir(&dir).expect("rmdir chroot target");
        if euid_is_root {
            assert_eq!(
                code, 0,
                "as root the chroot should succeed (in the child): \
                 5 = not inside an empty root"
            );
        } else {
            assert_eq!(
                code, 2,
                "unprivileged the chroot must fail closed (Hardening): \
                 3 = wrong error, 6 = the working directory moved"
            );
        }
    }
}
