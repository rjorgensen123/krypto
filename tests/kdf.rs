// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the KDF layer: HMAC-SHA256 over a derived key,
//! the shape an audit chain uses.

use krypto::{hmac_sha256, MasterKey};

fn test_master(tag: &str) -> MasterKey {
    let path = std::env::temp_dir().join(format!(
        "krypto-test-master-kdf-{}-{tag}.key",
        std::process::id()
    ));
    std::fs::write(&path, [7u8; 32]).unwrap();
    let mk = MasterKey::from_secret_file(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    mk
}

#[test]
fn hmac_cross_check_against_python() {
    // Cross-computed with Python (hashlib/hmac, manual HKDF-SHA256):
    // master=[7u8;32], salt=b"saltsalt", info=b"krypto/test/v1",
    // data=b"audit-kjede-test". Binds the Rust implementation to an
    // independent one — the interop guarantee for non-Rust consumers.
    // NOTE: the input bytes are a frozen test vector — do not "translate" them.
    let mk = test_master("py");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let mac = hmac_sha256(&dk, b"audit-kjede-test").unwrap();
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "de2b3692570bad46a6958de38c55618636d9f72d6a699a1fc61e736a283c4357"
    );
}

#[test]
fn hmac_deterministic_and_context_separated() {
    let mk = test_master("det");
    let dk = mk.derive(b"ctx/a", b"salt").unwrap();
    let m1 = hmac_sha256(&dk, b"data").unwrap();
    let m2 = hmac_sha256(&dk, b"data").unwrap();
    assert_eq!(m1, m2, "same key+data must give the same MAC");

    let dk2 = mk.derive(b"ctx/b", b"salt").unwrap();
    assert_ne!(
        hmac_sha256(&dk2, b"data").unwrap(),
        m1,
        "a different context must give a different MAC"
    );
    assert_ne!(
        hmac_sha256(&dk, b"other-data").unwrap(),
        m1,
        "different data must give a different MAC"
    );
}

#[test]
fn oversized_master_key_file_is_rejected() {
    use krypto::Error;
    let path = std::env::temp_dir().join(format!("krypto-big-master-{}.key", std::process::id()));
    std::fs::write(&path, vec![7u8; 8192]).unwrap(); // > the 4 KiB cap
    assert!(matches!(
        MasterKey::from_secret_file(&path),
        Err(Error::Format(_))
    ));
    let _ = std::fs::remove_file(&path);
}

/// A key file holds 32 to `MAX_MASTER_KEY_BYTES` bytes, both bounds included:
/// one byte under is `Format` and says how many bytes it got, the cap is
/// accepted, and one byte over is `Format`, too big.
#[test]
fn master_key_file_bounds_hold_on_both_sides() {
    use krypto::{Error, MAX_MASTER_KEY_BYTES};
    let dir = kdf_dir("file-bounds");
    let path = dir.join("bounds.key");

    std::fs::write(&path, [7u8; 31]).unwrap();
    match MasterKey::from_secret_file(&path) {
        Err(Error::Format(m)) => {
            assert!(
                m.contains("at least 32 bytes, got 31"),
                "unexpected message: {m}"
            )
        }
        other => panic!("expected Format, got {:?}", other.map(|_| ())),
    }

    std::fs::write(&path, vec![7u8; MAX_MASTER_KEY_BYTES]).unwrap();
    assert!(
        MasterKey::from_secret_file(&path).is_ok(),
        "a key file at the cap must pass"
    );

    std::fs::write(&path, vec![7u8; MAX_MASTER_KEY_BYTES + 1]).unwrap();
    match MasterKey::from_secret_file(&path) {
        Err(Error::Format(m)) => {
            assert!(m.contains("too big"), "unexpected message: {m}")
        }
        other => panic!("expected Format, got {:?}", other.map(|_| ())),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `info` and `salt` are bounded, like every other input the crate takes.
///
/// Both reach the API from command lines and config files (`krypto-cli`'s
/// `--context` and `--salt`), and an unbounded one is work whose size an
/// attacker chooses. The cap has room to spare over the longest real use: the
/// store's `krypto/store/v1|` prefix plus a 512-byte key name. One byte over
/// is `Format`, with a message that names the input and its limit.
#[test]
fn oversized_info_and_salt_are_rejected() {
    use krypto::{Error, MAX_DERIVE_INPUT_BYTES};
    let mk = test_master("bounds");
    let at_cap = vec![b'x'; MAX_DERIVE_INPUT_BYTES];
    let over = vec![b'x'; MAX_DERIVE_INPUT_BYTES + 1];

    assert!(
        mk.derive(&at_cap, b"saltsalt").is_ok(),
        "info at the cap must pass"
    );
    assert!(
        mk.derive(b"krypto/test/v1", &at_cap).is_ok(),
        "salt at the cap must pass"
    );
    for (what, result) in [
        ("`info`", mk.derive(&over, b"saltsalt")),
        ("`salt`", mk.derive(b"krypto/test/v1", &over)),
    ] {
        match result {
            Err(Error::Format(m)) => assert!(
                m.contains(what) && m.ends_with(&format!("max {MAX_DERIVE_INPUT_BYTES}")),
                "{what}: unexpected message: {m}"
            ),
            other => panic!("{what}: expected Format, got {:?}", other.map(|_| ())),
        }
    }
}

/// One type, one rule: `from_bytes` caps the key at the same size
/// `from_secret_file` does. Two ways in must not mean two different limits.
#[test]
fn oversized_master_key_from_bytes_is_rejected() {
    use krypto::{Error, SecretBuf, MAX_MASTER_KEY_BYTES};
    let at_cap = SecretBuf::from_vec(vec![7u8; MAX_MASTER_KEY_BYTES]).unwrap();
    let over = SecretBuf::from_vec(vec![7u8; MAX_MASTER_KEY_BYTES + 1]).unwrap();
    assert!(
        MasterKey::from_bytes(at_cap).is_ok(),
        "a key at the cap must pass"
    );
    assert!(
        matches!(MasterKey::from_bytes(over), Err(Error::Format(_))),
        "a key one byte over the cap was accepted"
    );
}

/// The lower bound holds on `from_bytes` too: a key one byte short of 32 is
/// `Format`, and the message says how many bytes it got.
#[test]
fn short_master_key_from_bytes_is_rejected() {
    use krypto::{Error, SecretBuf};
    let short = SecretBuf::from_vec(vec![7u8; 31]).unwrap();
    match MasterKey::from_bytes(short) {
        Err(Error::Format(m)) => {
            assert!(
                m.contains("at least 32 bytes, got 31"),
                "unexpected message: {m}"
            )
        }
        other => panic!("expected Format, got {:?}", other.map(|_| ())),
    }
}

/// Empty `info` must be rejected: it IS the purpose separation in HKDF.
///
/// Without it the audit-MAC key and the token-sealing key would have been
/// **identical** — a failure impossible to spot after the fact, and one a
/// missing config value is enough to trigger.
#[test]
fn empty_info_is_rejected() {
    let mk = test_master("empty-info");
    // The caller's input, so `Format` (0.7.3; it was `Hardening`).
    assert!(
        matches!(mk.derive(b"", b"saltsalt"), Err(krypto::Error::Format(_))),
        "empty info was accepted, or not as Format"
    );
    assert!(mk.derive(b"krypto/test/v1", b"saltsalt").is_ok());
}

/// Different purposes must give different keys — that is the whole point of `info`.
#[test]
fn different_purposes_give_different_keys() {
    let mk = test_master("separation");
    let a = mk.derive(b"example/audit-mac/v1", b"saltsalt").unwrap();
    let b = mk.derive(b"example/token/v1", b"saltsalt").unwrap();
    let mac_a = krypto::hmac_sha256(&a, b"same data").unwrap();
    let mac_b = krypto::hmac_sha256(&b, b"same data").unwrap();
    assert_ne!(mac_a, mac_b, "two purposes produced the same key");
}

/// The key id is frozen: blobs carry it, and `krypto-cli` has always written
/// this value for this key (0.8.0, when it moved into the library).
#[test]
fn key_id_is_frozen() {
    let key = krypto::SecretBuf::from_vec((0u8..32).collect()).unwrap();
    let mk = MasterKey::from_bytes(key).unwrap();
    assert_eq!(
        krypto::hex::encode(&mk.key_id().unwrap()).unwrap(),
        "e5b56819c0e7cf09e3fc10357542f41c"
    );
}

// --- what kind of path the master key is read from ---

/// The key the tests below deliver, in whatever way.
#[cfg(unix)]
const PIPE_KEY: [u8; 32] = [5u8; 32];

/// A fresh directory for one test.
fn kdf_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("krypto-kdf-dir-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The key id of `PIPE_KEY` read from a regular file in `dir`.
#[cfg(unix)]
fn key_id_from_regular_file(dir: &std::path::Path) -> [u8; 16] {
    let path = dir.join("regular.key");
    std::fs::write(&path, PIPE_KEY).unwrap();
    MasterKey::from_secret_file(&path)
        .unwrap()
        .key_id()
        .unwrap()
}

/// Make a FIFO at `p`.
#[cfg(unix)]
fn make_fifo(p: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
}

/// The outcome of reading a master key in another thread: its key id, or the
/// error.
#[cfg(unix)]
type ReadOutcome = std::sync::mpsc::Receiver<Result<[u8; 16], krypto::Error>>;

/// Start `MasterKey::from_secret_file(path)` in a thread.
#[cfg(unix)]
fn read_key_in_thread(path: &std::path::Path) -> (std::thread::JoinHandle<()>, ReadOutcome) {
    let (tx, rx) = std::sync::mpsc::channel();
    let path = path.to_path_buf();
    let reader = std::thread::spawn(move || {
        let _ = tx.send(MasterKey::from_secret_file(&path).and_then(|mk| mk.key_id()));
    });
    (reader, rx)
}

/// Wait at most 10 s for the read, so a read that never returns fails the
/// test instead of hanging the suite. On timeout the FIFO is opened for
/// writing and closed, which lets a blocked `open` go, and the test fails.
#[cfg(unix)]
fn outcome_within_time_limit(
    outcome: &ReadOutcome,
    fifo: &std::path::Path,
) -> Result<[u8; 16], krypto::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    match outcome.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(outcome) => outcome,
        Err(_) => {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo);
            panic!(
                "reading the key from the FIFO {} did not return",
                fifo.display()
            );
        }
    }
}

/// Open the FIFO for writing once a reader has it open, write `PIPE_KEY` and
/// close. The open does not block: with no reader it fails with `ENXIO` and is
/// tried again, for at most 10 s, so a reader that never comes fails the test
/// instead of hanging it.
#[cfg(unix)]
fn deliver_key(fifo: &std::path::Path) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(fifo)
        {
            Ok(mut writer) => {
                writer.write_all(&PIPE_KEY).unwrap();
                return;
            }
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no reader opened the FIFO {} within 10 s",
                    fifo.display()
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => panic!("cannot open the FIFO {} for writing: {e}", fifo.display()),
        }
    }
}

/// A named pipe is an accepted source of the key: what a writer delivers
/// before it closes is the key, the same as those bytes in a regular file.
#[cfg(unix)]
#[test]
fn a_key_delivered_through_a_named_pipe_is_read() {
    let dir = kdf_dir("pipe");
    let expected = key_id_from_regular_file(&dir);
    let fifo = dir.join("key.fifo");
    make_fifo(&fifo);
    let writer = {
        let fifo = fifo.clone();
        std::thread::spawn(move || deliver_key(&fifo))
    };
    let (reader, outcome) = read_key_in_thread(&fifo);
    let key_id = outcome_within_time_limit(&outcome, &fifo).unwrap();
    assert_eq!(key_id, expected, "the key from the pipe is not the key");
    reader.join().unwrap();
    writer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// With no writer at the named pipe the call waits, and reads the key once a
/// writer has delivered it and closed.
#[cfg(unix)]
#[test]
fn a_named_pipe_without_a_writer_makes_the_read_wait() {
    let dir = kdf_dir("pipe-wait");
    let expected = key_id_from_regular_file(&dir);
    let fifo = dir.join("key.fifo");
    make_fifo(&fifo);
    let (reader, outcome) = read_key_in_thread(&fifo);
    assert!(
        matches!(
            outcome.recv_timeout(std::time::Duration::from_millis(300)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "the read returned before a writer came"
    );
    deliver_key(&fifo);
    let key_id = outcome_within_time_limit(&outcome, &fifo).unwrap();
    assert_eq!(key_id, expected, "the key from the pipe is not the key");
    reader.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A directory is `Io`.
#[test]
fn a_directory_as_the_key_file_is_io() {
    let dir = kdf_dir("directory");
    match MasterKey::from_secret_file(&dir) {
        Err(krypto::Error::Io(_)) => {}
        other => panic!("expected Io, got {:?}", other.map(|_| ())),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty source is `Format`: it holds fewer than 32 bytes.
#[cfg(unix)]
#[test]
fn dev_null_as_the_key_file_is_format() {
    match MasterKey::from_secret_file("/dev/null") {
        Err(krypto::Error::Format(m)) => {
            assert!(
                m.contains("at least 32 bytes, got 0"),
                "unexpected message: {m}"
            )
        }
        other => panic!("expected Format, got {:?}", other.map(|_| ())),
    }
}

/// An endless source is `Format`, too big.
#[cfg(unix)]
#[test]
fn dev_zero_as_the_key_file_is_format_too_big() {
    match MasterKey::from_secret_file("/dev/zero") {
        Err(krypto::Error::Format(m)) => {
            assert!(m.contains("too big"), "unexpected message: {m}")
        }
        other => panic!("expected Format, got {:?}", other.map(|_| ())),
    }
}

/// A symbolic link to a regular key file is followed.
#[cfg(unix)]
#[test]
fn a_symlink_to_a_key_file_is_followed() {
    let dir = kdf_dir("symlink");
    let expected = key_id_from_regular_file(&dir);
    let link = dir.join("link.key");
    std::os::unix::fs::symlink(dir.join("regular.key"), &link).unwrap();
    assert_eq!(
        MasterKey::from_secret_file(&link)
            .unwrap()
            .key_id()
            .unwrap(),
        expected,
        "the key read through the link is not the key"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
