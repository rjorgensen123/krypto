//! Process hardening tests.
//!
//! The dangerous calls run in a FORKED CHILD so that a success (e.g. the
//! suite running as root in CI) cannot damage the test binary itself. The
//! fork tests are compiled out under Miri — fork and the syscalls are
//! unsupported there, and the ffi layer is a no-op anyway.

#[test]
fn harden_is_ok_and_idempotent() {
    // Must succeed without special privileges (lowers limits / sets dumpable).
    krypto::harden_process().expect("harden_process should succeed");
    // Idempotent: safe to call multiple times.
    krypto::harden_process().expect("harden_process should be idempotent");
}

#[test]
fn no_new_privs_is_ok_and_idempotent() {
    // Needs no privileges, and setting the bit twice is fine. Affects only
    // privilege-gaining execve, which the test process never does.
    krypto::no_new_privs().expect("no_new_privs should succeed");
    krypto::no_new_privs().expect("no_new_privs should be idempotent");
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

    #[test]
    fn close_inherited_fds_closes_above_stderr() {
        // Open the fd in the PARENT so the child does not allocate before
        // the syscall; the fork gives the child its own copy of the table.
        let f = std::fs::File::open("/etc/os-release")
            .or_else(|_| std::fs::File::open("/etc/hostname"))
            .expect("no readable /etc file for the test");
        let fd = f.as_raw_fd();
        let code = in_child(|| {
            if krypto::close_inherited_fds().is_err() {
                return 3;
            }
            // SAFETY: fcntl on a plain integer descriptor.
            let gone = unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1;
            if gone {
                0
            } else {
                4
            }
        });
        assert_eq!(code, 0, "3 = call failed, 4 = the fd survived");
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
        // chroot succeeds (and only the child is jailed); unprivileged it
        // must fail closed with Error::Hardening (EPERM).
        let dir = std::env::temp_dir().join(format!("krypto-chroot-test-{}", std::process::id()));
        std::fs::create_dir(&dir).expect("mkdir for chroot target");
        let euid_is_root = unsafe { libc::geteuid() } == 0;
        let target = dir.clone();
        let code = in_child(move || match krypto::drop_filesystem(&target) {
            Ok(()) => 0,
            Err(krypto::Error::Hardening(_)) => 2,
            Err(_) => 3,
        });
        std::fs::remove_dir(&dir).expect("rmdir chroot target");
        if euid_is_root {
            assert_eq!(code, 0, "as root the chroot should succeed (in the child)");
        } else {
            assert_eq!(
                code, 2,
                "unprivileged the chroot must fail closed (Hardening)"
            );
        }
    }
}
