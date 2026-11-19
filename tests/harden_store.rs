// SPDX-License-Identifier: MIT OR Apache-2.0
//! `close_inherited_fds` and open stores (0.9.0): the call refuses while a
//! `SecretStore` in the process holds its lock, and runs once none does.
//!
//! The count of held locks is process-wide, so these tests have a binary of
//! their own and run one at a time. Where the call succeeds it closes every
//! descriptor above stderr, so it runs in a forked child, as in
//! `tests/harden.rs`; where it refuses it closes nothing and runs in the test.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use krypto::{Error, MasterKey, SecretBuf, SecretStore};

/// One test at a time: a store open in another test would make the call
/// refuse, and a child forked while another test holds krypto's guard on the
/// count would wait for it forever.
fn one_at_a_time() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn master(byte: u8) -> MasterKey {
    MasterKey::from_bytes(SecretBuf::from_vec(vec![byte; 32]).unwrap()).unwrap()
}

fn value(bytes: &[u8]) -> SecretBuf {
    SecretBuf::from_vec(bytes.to_vec()).unwrap()
}

/// A new, empty directory for one test.
fn scratch_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("krypto-harden-store-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// What `close_inherited_fds` answers in a forked child: 0 = it closed,
/// 3 = it refused with `Hardening`, 4 = another error. The child makes the
/// call and `_exit`s; glibc's atfork handlers make the allocation on the
/// error path safe.
fn close_in_child() -> i32 {
    // SAFETY: fork(); the child never returns, only _exits.
    unsafe {
        match libc::fork() {
            -1 => panic!("fork failed"),
            0 => libc::_exit(match krypto::close_inherited_fds() {
                Ok(()) => 0,
                Err(Error::Hardening(_)) => 3,
                Err(_) => 4,
            }),
            pid => {
                let mut status = 0;
                assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
                assert!(libc::WIFEXITED(status), "child did not exit normally");
                libc::WEXITSTATUS(status)
            }
        }
    }
}

/// `close_inherited_fds` refuses in this process, with the message that says
/// what is wrong and what to do.
fn assert_refuses(when: &str) {
    match krypto::close_inherited_fds() {
        Err(Error::Hardening(m)) => assert!(
            m.contains("a SecretStore is open in this process")
                && m.contains("before a store is opened, or after every open store is dropped"),
            "{when}: unexpected message: {m}"
        ),
        other => panic!("{when}: expected Hardening, got {other:?}"),
    }
}

/// T1: with a store open, the call refuses and closes nothing: the handle
/// still writes and reads, and a second `open` of the file is still refused,
/// so its lock is intact.
#[test]
fn refuses_while_a_store_holds_its_lock() {
    let _serial = one_at_a_time();
    let mk = master(7);
    let dir = scratch_dir("refuses");
    let path = dir.join("store");
    let mut s = SecretStore::open(&path, &mk).unwrap();

    assert_refuses("store open");
    s.put("a", &value(b"value")).unwrap();
    s.get("a").unwrap().expose(|b| assert_eq!(b, b"value"));
    match SecretStore::open(&path, &mk) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "{e}"),
        other => panic!("expected Io, got {:?}", other.map(|_| ())),
    }

    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// T2: once the store is dropped the call runs, also after `rotate` and
/// after `upgrade`. They hand the lock on to the new handle, so the call
/// still refuses while that handle lives, and runs once it is dropped.
#[test]
fn runs_once_the_store_is_dropped_also_after_rotate_and_upgrade() {
    let _serial = one_at_a_time();
    let (mk, new_mk) = (master(7), master(8));
    let dir = scratch_dir("dropped");

    let mut s = SecretStore::open(dir.join("plain"), &mk).unwrap();
    s.put("a", &value(b"value")).unwrap();
    drop(s);
    assert_eq!(close_in_child(), 0, "after drop: 3 = refused, 4 = error");

    let mut s = SecretStore::open(dir.join("rotated"), &mk).unwrap();
    s.put("a", &value(b"value")).unwrap();
    let rotated = s.rotate(&new_mk).unwrap();
    assert_refuses("after rotate");
    drop(rotated);
    assert_eq!(close_in_child(), 0, "after rotate: 3 = refused, 4 = error");

    let mut s = SecretStore::open_with_version(dir.join("upgraded"), &mk, 1).unwrap();
    s.put("a", &value(b"value")).unwrap();
    let upgraded = s.upgrade().unwrap();
    assert_eq!(upgraded.version(), 2);
    assert_refuses("after upgrade");
    drop(upgraded);
    assert_eq!(close_in_child(), 0, "after upgrade: 3 = refused, 4 = error");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A lock taken by an `open` that then fails, by a `rotate` or an `upgrade`
/// that fails, or by a handle that a panic unwinds, is no longer counted
/// afterwards. The failed `rotate` fails at the write, after the lock has
/// moved to the new handle; root can write in the directory it uses, so
/// that part is skipped as root.
#[test]
fn failed_opens_rotates_and_upgrades_leave_no_lock_counted() {
    let _serial = one_at_a_time();
    let (mk, other_mk) = (master(7), master(8));
    let dir = scratch_dir("failed");

    // The lock is taken first; then the file turns out not to be a store.
    let not_a_store = dir.join("not-a-store");
    std::fs::write(&not_a_store, b"important = true\n").unwrap();
    let opened = SecretStore::open(&not_a_store, &mk);
    assert!(
        matches!(opened, Err(Error::Format(_))),
        "{:?}",
        opened.map(|_| ())
    );
    assert_eq!(close_in_child(), 0, "failed open: 3 = refused, 4 = error");

    // A v1 file opens under another master key, and `upgrade` fails when it
    // decrypts the entry.
    let v1 = dir.join("v1");
    let mut s = SecretStore::open_with_version(&v1, &mk, 1).unwrap();
    s.put("a", &value(b"value")).unwrap();
    drop(s);
    let s = SecretStore::open(&v1, &other_mk).unwrap();
    assert!(matches!(s.upgrade().map(|_| ()), Err(Error::Auth)));
    assert_eq!(
        close_in_child(),
        0,
        "failed upgrade: 3 = refused, 4 = error"
    );

    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        let closed = dir.join("closed");
        std::fs::create_dir(&closed).unwrap();
        let s = SecretStore::open(closed.join("store"), &mk).unwrap();
        set_mode(&closed, 0o555); // the write cannot create its tmp file
        let rotated = s.rotate(&other_mk).map(|_| ());
        set_mode(&closed, 0o755);
        assert!(matches!(rotated, Err(Error::Io(_))), "{rotated:?}");
        assert_eq!(close_in_child(), 0, "failed rotate: 3 = refused, 4 = error");
    }

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _s = SecretStore::open(dir.join("unwound"), &mk).unwrap();
        panic!("a panic with a store open");
    }));
    assert!(unwound.is_err());
    assert_eq!(close_in_child(), 0, "after a panic: 3 = refused, 4 = error");

    let _ = std::fs::remove_dir_all(&dir);
}

/// T3: with two stores open the call refuses, with one of them dropped it
/// still refuses, and with both dropped it runs.
#[test]
fn refuses_until_every_open_store_is_dropped() {
    let _serial = one_at_a_time();
    let mk = master(7);
    let dir = scratch_dir("two");
    let first = SecretStore::open(dir.join("first"), &mk).unwrap();
    let second = SecretStore::open(dir.join("second"), &mk).unwrap();

    assert_refuses("two stores open");
    drop(first);
    assert_refuses("one store open");
    drop(second);
    assert_eq!(close_in_child(), 0, "none open: 3 = refused, 4 = error");

    let _ = std::fs::remove_dir_all(&dir);
}

/// T5: a store opened without a lock holds no descriptor, and does not make
/// the call refuse. The directory cannot be written and has no lock file, so
/// `open` goes ahead without one. Root can write in it, so the test is
/// skipped as root.
#[test]
fn a_store_without_a_lock_does_not_make_it_refuse() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root can create the lock file in any directory");
        return;
    }
    let _serial = one_at_a_time();
    let mk = master(7);
    let dir = scratch_dir("no-lock");
    let path = dir.join("store");
    drop(SecretStore::open(&path, &mk).unwrap());
    std::fs::remove_file(dir.join(".store.lock")).unwrap();

    set_mode(&dir, 0o555);
    let opened = SecretStore::open(&path, &mk);
    let lock_file_made = dir.join(".store.lock").exists();
    let code = close_in_child();
    let opened = opened.map(|_| ());
    set_mode(&dir, 0o755);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(opened.is_ok(), "{opened:?}");
    assert!(!lock_file_made, "the store took a lock");
    assert_eq!(code, 0, "3 = refused, 4 = error");
}
