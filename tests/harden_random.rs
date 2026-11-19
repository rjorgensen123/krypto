// SPDX-License-Identifier: MIT OR Apache-2.0
//! `close_inherited_fds` and the random source (0.9.0). After closing, the
//! call asks the random source for one byte. Where the `getrandom` crate
//! reads `/dev/urandom` through a descriptor it keeps, and that descriptor
//! was open before the call, the source no longer answers: the call answers
//! `Hardening`, and krypto hands out no random bytes in that process any
//! more. Where the kernel's call is in use, the call succeeds as before.
//!
//! Each child finds out which source it uses, by looking for a descriptor on
//! `/dev/urandom`, and checks what that case must give, so the tests hold in
//! both. getrandom's own switch forces the fallback:
//! `RUSTFLAGS='--cfg getrandom_test_linux_fallback'`.
//!
//! The refusal is process-wide and permanent, and the call closes every
//! descriptor above stderr, so all of it runs in forked children, and the
//! test process itself draws no random bytes: a descriptor on `/dev/urandom`
//! opened here would be inherited by every child. The tests run one at a
//! time, so no child is forked while another test is inside krypto.

use std::io::Write;
use std::os::unix::io::IntoRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use krypto::password::{self, Preset};
use krypto::{Alg, Error, MasterKey, SecretBuf, SecretStore, SecretString};

/// Exit code of a child that found the kernel's call in use and saw what it
/// must give.
const KERNEL_CALL: i32 = 10;
/// Exit code of a child that found the `/dev/urandom` fallback in use and saw
/// what it must give.
const URANDOM_FALLBACK: i32 = 11;
/// Exit code of a child that found something wrong; it says what on stderr.
const FAILED: i32 = 1;
/// Exit code of a child that panicked.
const PANICKED: i32 = 2;

/// What a request for random bytes answers once the source is found closed.
const SOURCE_CLOSED: &str = "the random source was closed by close_inherited_fds";
/// What `close_inherited_fds` answers when it finds the source closed.
const SOURCE_SILENT: &str = "the random source does not answer after the descriptors were closed";

/// One test at a time: a child forked while another test is inside krypto
/// could inherit a lock that is never released in it.
fn one_at_a_time() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A new, empty directory for one test.
fn scratch_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("krypto-harden-random-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `body` in a forked child and return its exit code: the code `body`
/// returns, [`FAILED`] when it returns an error, which it writes to stderr,
/// or [`PANICKED`].
fn in_child(body: impl FnOnce() -> Result<i32, String>) -> i32 {
    // SAFETY: fork(); the child never returns, only _exits.
    unsafe {
        match libc::fork() {
            -1 => panic!("fork failed"),
            0 => {
                let code = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
                    Ok(Ok(code)) => code,
                    Ok(Err(why)) => {
                        let _ = std::io::stderr().write_all(format!("child: {why}\n").as_bytes());
                        FAILED
                    }
                    Err(_) => PANICKED,
                };
                libc::_exit(code)
            }
            pid => {
                let mut status = 0;
                assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
                assert!(libc::WIFEXITED(status), "child did not exit normally");
                libc::WEXITSTATUS(status)
            }
        }
    }
}

/// Check the child's exit code, and say which random source it found.
fn assert_child_passed(code: i32) {
    match code {
        KERNEL_CALL => println!("random source in the child: the kernel's call"),
        URANDOM_FALLBACK => println!("random source in the child: /dev/urandom"),
        FAILED => panic!("the child found an error; its message is on stderr"),
        PANICKED => panic!("the child panicked"),
        other => panic!("unexpected exit code {other} from the child"),
    }
}

/// The descriptors above stderr open on `/dev/urandom` in this process.
fn urandom_descriptors() -> Result<Vec<i32>, String> {
    let entries =
        std::fs::read_dir("/proc/self/fd").map_err(|e| format!("reading /proc/self/fd: {e}"))?;
    let mut fds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading /proc/self/fd: {e}"))?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let target = std::fs::read_link(entry.path());
        if fd > 2 && target.is_ok_and(|t| t == Path::new("/dev/urandom")) {
            fds.push(fd);
        }
    }
    Ok(fds)
}

fn master() -> Result<MasterKey, String> {
    let key = SecretBuf::from_vec(vec![7; 32]).map_err(|e| format!("master key: {e:?}"))?;
    MasterKey::from_bytes(key).map_err(|e| format!("master key: {e:?}"))
}

/// `SecretBuf::random`, `random_bytes`, `seal` and `password::hash` work.
fn random_bytes_work() -> Result<(), String> {
    let dk = master()?
        .derive(b"krypto/test/v1", b"saltsalt")
        .map_err(|e| format!("derive: {e:?}"))?;
    let plaintext = SecretBuf::from_vec(b"value".to_vec()).map_err(|e| format!("{e:?}"))?;
    let pw = SecretString::from_string("correct horse".into()).map_err(|e| format!("{e:?}"))?;
    SecretBuf::random(32).map_err(|e| format!("SecretBuf::random: {e:?}"))?;
    krypto::random_bytes(32).map_err(|e| format!("random_bytes: {e:?}"))?;
    krypto::seal(&dk, &[1; 16], &plaintext, Alg::Aegis256).map_err(|e| format!("seal: {e:?}"))?;
    password::hash(&pw, Preset::Interactive).map_err(|e| format!("password::hash: {e:?}"))?;
    Ok(())
}

/// `SecretBuf::random`, `random_bytes`, `seal`, `password::hash` and creating
/// a new store at `store` each answer `Hardening`, saying the source was
/// closed.
fn every_request_refused(when: &str, store: &Path) -> Result<(), String> {
    let refused = |what: &str, got: Result<(), Error>| match got {
        Err(Error::Hardening(m)) if m.contains(SOURCE_CLOSED) => Ok(()),
        other => Err(format!(
            "{what} {when}: expected Hardening saying the source was closed, got {other:?}"
        )),
    };
    let mk = master()?;
    let dk = mk
        .derive(b"krypto/test/v1", b"saltsalt")
        .map_err(|e| format!("derive: {e:?}"))?;
    let plaintext = SecretBuf::from_vec(b"value".to_vec()).map_err(|e| format!("{e:?}"))?;
    let pw = SecretString::from_string("correct horse".into()).map_err(|e| format!("{e:?}"))?;

    refused("SecretBuf::random", SecretBuf::random(32).map(|_| ()))?;
    refused("random_bytes", krypto::random_bytes(32).map(|_| ()))?;
    refused(
        "seal",
        krypto::seal(&dk, &[1; 16], &plaintext, Alg::Aegis256).map(|_| ()),
    )?;
    refused(
        "password::hash",
        password::hash(&pw, Preset::Interactive).map(|_| ()),
    )?;
    refused("a new store", SecretStore::open(store, &mk).map(|_| ()))?;
    Ok(())
}

/// Child of [`close_after_random_bytes_were_drawn`].
fn draw_then_close(dir: &Path, file: &Path) -> Result<i32, String> {
    if !urandom_descriptors()?.is_empty() {
        return Err(
            "a descriptor on /dev/urandom was open before the child drew random bytes".into(),
        );
    }
    krypto::random_bytes(16).map_err(|e| format!("random_bytes before the closing: {e:?}"))?;
    match urandom_descriptors()?.as_slice() {
        [] => {
            krypto::close_inherited_fds().map_err(|e| format!("close_inherited_fds: {e:?}"))?;
            random_bytes_work()?;
            Ok(KERNEL_CALL)
        }
        [source] => fallback_after_close(*source, dir, file),
        more => Err(format!("several descriptors on /dev/urandom: {more:?}")),
    }
}

/// The fallback case: the source's descriptor `source` was open before the
/// call. `file` is an ordinary non-empty file, opened until it takes that
/// number.
fn fallback_after_close(source: i32, dir: &Path, file: &Path) -> Result<i32, String> {
    match krypto::close_inherited_fds() {
        Err(Error::Hardening(m)) if m.contains(SOURCE_SILENT) => {}
        other => {
            return Err(format!(
                "close_inherited_fds after a draw: expected Hardening saying the source does \
                 not answer, got {other:?}"
            ))
        }
    }
    every_request_refused("after the closing", &dir.join("store-1"))?;

    // The descriptors are given up before the second call closes them.
    let mut opened = Vec::new();
    loop {
        let f = std::fs::File::open(file).map_err(|e| format!("opening the file: {e}"))?;
        let fd = f.into_raw_fd();
        opened.push(fd);
        if fd == source {
            break;
        }
        if fd > source {
            return Err(format!(
                "the file got descriptor {fd}, past the source's {source}"
            ));
        }
    }
    every_request_refused(
        "with a file under the source's number",
        &dir.join("store-2"),
    )?;

    match krypto::close_inherited_fds() {
        Err(Error::Hardening(m)) if m.contains(SOURCE_CLOSED) => {}
        other => {
            return Err(format!(
                "a second close_inherited_fds: expected Hardening saying the source was \
                 closed, got {other:?}"
            ))
        }
    }
    Ok(URANDOM_FALLBACK)
}

/// Child of [`close_before_anything_drew_random_bytes`].
fn close_then_draw() -> Result<i32, String> {
    if !urandom_descriptors()?.is_empty() {
        return Err("a descriptor on /dev/urandom was open before the closing".into());
    }
    krypto::close_inherited_fds().map_err(|e| format!("close_inherited_fds: {e:?}"))?;
    let source = if urandom_descriptors()?.is_empty() {
        KERNEL_CALL
    } else {
        URANDOM_FALLBACK
    };
    SecretBuf::random(32).map_err(|e| format!("SecretBuf::random: {e:?}"))?;
    krypto::random_bytes(32).map_err(|e| format!("random_bytes: {e:?}"))?;
    Ok(source)
}

/// After random bytes were drawn: with the kernel's call the closing succeeds
/// and random bytes still work. With the fallback the closing answers
/// `Hardening`, and from then on every request for random bytes, the salt of
/// `password::hash` and a new store's salt and key id included, answers
/// `Hardening`, also once an ordinary file holds the source's old number,
/// and so does a second closing.
#[test]
fn close_after_random_bytes_were_drawn() {
    let _serial = one_at_a_time();
    let dir = scratch_dir("drawn");
    let file = dir.join("ordinary-file");
    std::fs::write(&file, vec![0x5a; 4096]).unwrap();
    let code = in_child(|| draw_then_close(&dir, &file));
    let _ = std::fs::remove_dir_all(&dir);
    assert_child_passed(code);
}

/// Before anything drew random bytes, the closing succeeds with either
/// source, and random bytes work afterwards.
#[test]
fn close_before_anything_drew_random_bytes() {
    let _serial = one_at_a_time();
    let code = in_child(close_then_draw);
    assert_child_passed(code);
}
