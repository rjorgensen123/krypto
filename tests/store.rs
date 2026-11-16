// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for SecretStore.

use krypto::{Error, MasterKey, SecretBuf, SecretStore};

fn master(tag: &str) -> MasterKey {
    let p = std::env::temp_dir().join(format!(
        "krypto-store-master-{}-{tag}.key",
        std::process::id()
    ));
    std::fs::write(&p, [9u8; 32]).unwrap();
    let mk = MasterKey::from_secret_file(&p).unwrap();
    let _ = std::fs::remove_file(&p);
    mk
}

fn store_path(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("krypto-store-{}-{tag}.fst", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn put_get_roundtrip() {
    let mk = master("rt");
    let path = store_path("rt");
    let mut s = SecretStore::open(&path, &mk).unwrap();
    let secret = SecretBuf::from_vec(b"ssh-private-key".to_vec()).unwrap();
    s.put("service/alpha/ssh-key", &secret).unwrap();
    let out = s.get("service/alpha/ssh-key").unwrap();
    out.expose(|b| assert_eq!(b, b"ssh-private-key"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn missing_name_gives_keynotfound() {
    let mk = master("mn");
    let path = store_path("mn");
    let s = SecretStore::open(&path, &mk).unwrap();
    assert!(matches!(s.get("does-not-exist"), Err(Error::KeyNotFound)));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn persistence_across_reopen() {
    let mk = master("pe");
    let path = store_path("pe");
    {
        let mut s = SecretStore::open(&path, &mk).unwrap();
        s.put("a/b", &SecretBuf::from_vec(b"value-1".to_vec()).unwrap())
            .unwrap();
    }
    // New store object, same file + same master (same 32 bytes).
    let mk2 = master("pe");
    let s2 = SecretStore::open(&path, &mk2).unwrap();
    let out = s2.get("a/b").unwrap();
    out.expose(|b| assert_eq!(b, b"value-1"));
    let _ = std::fs::remove_file(&path);
}

// --- adversarial file input (the parser must never panic) ------------------ #

/// A valid store file made by this build, as **version 1** — the byte-offset
/// and tamper tests below speak about the frozen v1 format (since 0.9.0,
/// `open` creates v2 files; `open_with_version(.., 1)` pins v1).
fn valid_store_bytes(tag: &str) -> (std::path::PathBuf, MasterKey, Vec<u8>) {
    let mk = master(tag);
    let path = store_path(tag);
    {
        let mut s = SecretStore::open_with_version(&path, &mk, 1).unwrap();
        s.put("dev/x", &SecretBuf::from_vec(b"secret".to_vec()).unwrap())
            .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    (path, master(tag), bytes)
}

#[test]
fn wrong_magic_gives_format() {
    let (path, mk, mut bytes) = valid_store_bytes("magic");
    bytes[0] = b'X';
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        SecretStore::open(&path, &mk),
        Err(Error::Format(_))
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_version_gives_format() {
    let (path, mk, mut bytes) = valid_store_bytes("ver");
    bytes[4] = 99;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        SecretStore::open(&path, &mk),
        Err(Error::Format(_))
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn truncated_header_gives_format() {
    let (path, mk, bytes) = valid_store_bytes("trunc");
    std::fs::write(&path, &bytes[..10]).unwrap(); // shorter than the header
    assert!(matches!(
        SecretStore::open(&path, &mk),
        Err(Error::Format(_))
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn hostile_blob_length_gives_format_not_panic() {
    // Hand-crafted file: valid header + one entry with blen = u32::MAX and no
    // blob data. Without checked_add, off+blen could wrap and cause a slice panic.
    let mk = master("hostile");
    let path = store_path("hostile");
    let mut f = Vec::new();
    f.extend_from_slice(b"FST1"); // magic
    f.push(1); // version
    f.extend_from_slice(&[0u8; 16]); // salt
    f.extend_from_slice(&[0u8; 16]); // key_id
    f.extend_from_slice(&1u16.to_le_bytes()); // nlen = 1
    f.push(b'x'); // name
    f.extend_from_slice(&u32::MAX.to_le_bytes()); // blen = enormous
                                                  // (no blob bytes)
    std::fs::write(&path, &f).unwrap();
    assert!(matches!(
        SecretStore::open(&path, &mk),
        Err(Error::Format(_))
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn blob_is_bound_to_its_name() {
    // Change the name a blob sits under → get must give Auth (per-name DEK).
    // A v1 store, so `open` does not already reject the tampering (0.9.0 v2
    // files carry a container MAC over the entry table).
    let mk = master("bind");
    let path = store_path("bind");
    {
        let mut s = SecretStore::open_with_version(&path, &mk, 1).unwrap();
        s.put("a", &SecretBuf::from_vec(b"value".to_vec()).unwrap())
            .unwrap();
    }
    let mut bytes = std::fs::read(&path).unwrap();
    // The name "a" sits as one byte right after nlen (2 bytes) after the 37-byte header.
    let name_off = 37 + 2;
    assert_eq!(bytes[name_off], b'a');
    bytes[name_off] = b'z'; // rename the entry on disk
    std::fs::write(&path, &bytes).unwrap();
    let mk2 = master("bind");
    let s = SecretStore::open(&path, &mk2).unwrap();
    // The blob was sealed for "a" but now sits under "z" → the DEK does not match.
    assert!(matches!(s.get("z"), Err(Error::Auth)));
    let _ = std::fs::remove_file(&path);
}

/// A key id in a store that does not match is `Auth` — tampering (0.7.3).
///
/// A store holds one key generation, and `rotate` replaces it whole, so a blob
/// and its store never disagree on the key id unless one was changed. Before
/// 0.7.3 this gave `WrongKey`, the routing answer, so the change raised no
/// alarm.
#[test]
fn key_id_mismatch_in_a_store_gives_auth() {
    // A v1 store, so the tampering is caught by `get`, not already at `open`
    // by the v2 container MAC (0.9.0).
    let mk = master("gen");
    let path = store_path("gen");
    {
        let mut s = SecretStore::open_with_version(&path, &mk, 1).unwrap();
        s.put("a", &SecretBuf::from_vec(b"value".to_vec()).unwrap())
            .unwrap();
    }
    let original = std::fs::read(&path).unwrap();
    // The store header's key id is at 5+16=21; the entry "a" starts at 37 (nlen
    // 2, name 1, blen 4), so its blob starts at 44 and the blob's key id at 50.
    assert_eq!(&original[44..48], b"FAFN");
    for offset in [21, 50] {
        let mut bytes = original.clone();
        bytes[offset] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        let s = SecretStore::open(&path, &mk).unwrap();
        assert!(matches!(s.get("a"), Err(Error::Auth)), "offset {offset}");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_and_list() {
    let mk = master("dl");
    let path = store_path("dl");
    let mut s = SecretStore::open(&path, &mk).unwrap();
    s.put("dev/a", &SecretBuf::from_vec(b"1".to_vec()).unwrap())
        .unwrap();
    s.put("dev/b", &SecretBuf::from_vec(b"2".to_vec()).unwrap())
        .unwrap();
    s.put("other/c", &SecretBuf::from_vec(b"3".to_vec()).unwrap())
        .unwrap();
    assert_eq!(
        s.list("dev/"),
        vec!["dev/a".to_string(), "dev/b".to_string()]
    );
    s.delete("dev/a").unwrap();
    assert!(!s.contains("dev/a"));
    assert_eq!(s.list("dev/"), vec!["dev/b".to_string()]);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn oversized_store_file_is_rejected_no_oom() {
    // A bloated store file must give a Format error, not be read in unbounded.
    let mk = master("big");
    let path = store_path("big");
    std::fs::write(&path, vec![0u8; 20 * 1024 * 1024]).unwrap(); // > the 16 MiB cap
    assert!(matches!(
        SecretStore::open(&path, &mk),
        Err(Error::Format(_))
    ));
    let _ = std::fs::remove_file(&path);
}

/// Reading validates the name too, not just writing.
///
/// `put` has always fenced the character set, but a store file does not have to
/// come from `put` — a restore, a copy or tampering can put anything there. The
/// name travels in plaintext, and `list()` hands it to a consumer that logs it.
#[test]
fn illegal_key_name_in_the_file_is_rejected_on_load() {
    let (path, mk, mut bytes) = valid_store_bytes("loadname");
    // The store holds one key, "dev/x", stored in the clear. Swap the slash for
    // a newline: same length, still valid UTF-8, no longer printable ASCII.
    let at = bytes
        .windows(5)
        .position(|w| w == b"dev/x")
        .expect("the key name must be in the file in the clear");
    bytes[at + 3] = b'\n';
    std::fs::write(&path, &bytes).unwrap();
    assert!(
        matches!(SecretStore::open(&path, &mk), Err(Error::Format(_))),
        "a name with a newline must be refused on load, not handed to list()"
    );
    let _ = std::fs::remove_file(&path);
}

/// Key names are validated on character set, not just length.
///
/// Names are not secret and are exposed through `list()` — a name with a
/// newline could shift lines in a consumer's log, and an empty name is not a
/// key anyone can look up again.
#[test]
fn illegal_key_names_are_rejected() {
    let path = store_path("names");
    let mk = master("names");
    let mut store = SecretStore::open(&path, &mk).unwrap();
    let secret = SecretBuf::from_vec(b"x".to_vec()).unwrap();

    for (name, what) in [
        ("", "empty"),
        ("line\nbreak", "newline"),
        ("nul\0byte", "NUL"),
        ("æøå", "non-ASCII"),
        ("tab\there", "tab"),
    ] {
        assert!(
            store.put(name, &secret).is_err(),
            "illegal name accepted ({what}): {name:?}"
        );
    }

    // Too long.
    let long = "a".repeat(513);
    assert!(store.put(&long, &secret).is_err(), "overlong name accepted");

    // Ordinary names must still work.
    for legal in ["service/alpha", "api-token", "master.key.v2", "a b"] {
        store
            .put(legal, &secret)
            .unwrap_or_else(|e| panic!("legal name rejected {legal:?}: {e}"));
    }
}

// --- rotate (0.6.0 — the rotation action) ---

fn master_with(tag: &str, byte: u8) -> MasterKey {
    let p = std::env::temp_dir().join(format!(
        "krypto-store-master-{}-{tag}.key",
        std::process::id()
    ));
    std::fs::write(&p, [byte; 32]).unwrap();
    let mk = MasterKey::from_secret_file(&p).unwrap();
    let _ = std::fs::remove_file(&p);
    mk
}

#[test]
fn rotate_reencrypts_everything_under_the_new_master() {
    let old_mk = master_with("rot-old", 9);
    let new_mk = master_with("rot-new", 10);
    let path = store_path("rotate");

    let mut store = SecretStore::open(&path, &old_mk).unwrap();
    store
        .put("a", &SecretBuf::from_vec(b"first".to_vec()).unwrap())
        .unwrap();
    store
        .put("b", &SecretBuf::from_vec(b"second".to_vec()).unwrap())
        .unwrap();

    // Rotate: the returned handle is bound to the new master and reads back.
    let rotated = store.rotate(&new_mk).unwrap();
    rotated
        .get("a")
        .unwrap()
        .expose(|b| assert_eq!(b, b"first"));
    assert_eq!(rotated.list(""), vec!["a".to_string(), "b".to_string()]);
    drop(rotated); // one handle per file (0.7.2)

    // Reopening the FILE with the new master works; with the old master the
    // file no longer even opens (0.9.0): a v2 store checks the master key at
    // `open` through its key_check, so the old master is Auth right there.
    let reopened = SecretStore::open(&path, &new_mk).unwrap();
    assert_eq!(reopened.version(), 2);
    reopened
        .get("b")
        .unwrap()
        .expose(|b| assert_eq!(b, b"second"));
    drop(reopened);
    assert!(matches!(
        SecretStore::open(&path, &old_mk),
        Err(Error::Auth)
    ));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn rotate_with_the_wrong_master_leaves_the_file_untouched() {
    let mk = master_with("rot-fc", 9);
    let wrong = master_with("rot-fc-wrong", 11);
    let path = store_path("rotate-failclosed");

    // A v1 store: `open` does not check the master key on v1, so the wrong
    // master gets a handle and the failure shows up when rotate decrypts.
    let mut store = SecretStore::open_with_version(&path, &mk, 1).unwrap();
    store
        .put("a", &SecretBuf::from_vec(b"keep me".to_vec()).unwrap())
        .unwrap();

    drop(store); // one handle per file (0.7.2)

    // "Rotating" a store opened with the WRONG master fails on decrypt —
    // fail-closed, nothing written.
    let stale = SecretStore::open(&path, &wrong).unwrap();
    assert!(matches!(stale.rotate(&mk), Err(Error::Auth)));

    // The file is unchanged: the real master still reads it.
    let intact = SecretStore::open(&path, &mk).unwrap();
    intact
        .get("a")
        .unwrap()
        .expose(|b| assert_eq!(b, b"keep me"));

    let _ = std::fs::remove_file(&path);
}

/// A fresh directory for one test, so files can be planted next to the store.
fn store_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("krypto-store-dir-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[cfg(unix)]
fn mode_of(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).unwrap().mode() & 0o777
}

/// 0.7.2: the tmp name carries a random part. A symlink planted at the name
/// the tmp file had before (`.tmp-<pid>-<name>`) made the store overwrite the
/// file it pointed to; now that name is not used at all, and no tmp file is
/// left behind. The real tmp name cannot be known in advance, so this test
/// does not reach the `create_new` that refuses a link planted there.
#[cfg(unix)]
#[test]
fn a_symlink_at_the_old_predictable_tmp_name_is_not_used() {
    let mk = master("plant");
    let dir = store_dir("plant");
    let victim = dir.join("victim.conf");
    std::fs::write(&victim, b"important = true\n").unwrap();
    let planted = dir.join(format!(".tmp-{}-store", std::process::id()));
    std::os::unix::fs::symlink(&victim, &planted).unwrap();

    let mut s = SecretStore::open(dir.join("store"), &mk).unwrap();
    s.put("a", &SecretBuf::from_vec(b"x".to_vec()).unwrap())
        .unwrap();

    assert_eq!(std::fs::read(&victim).unwrap(), b"important = true\n");
    assert_eq!(mode_of(&dir.join("store")), 0o600);
    let left: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with(".tmp-") && dir.join(n) != planted)
        .collect();
    assert!(left.is_empty(), "tmp files left behind: {left:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 0.7.2: an existing store file with wider permissions gets 0600 on open, as
/// every write gives it. Before, it stayed open until the next write.
#[cfg(unix)]
#[test]
fn an_existing_store_file_gets_0600_on_open() {
    use std::os::unix::fs::PermissionsExt;
    let mk = master("perm");
    let path = store_path("perm");
    SecretStore::open(&path, &mk).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    SecretStore::open(&path, &mk).unwrap();
    assert_eq!(mode_of(&path), 0o600);
    let _ = std::fs::remove_file(&path);
}

/// 0.7.2: a store never grows past what `open` accepts. Ordinary puts could
/// write a file larger than `MAX_STORE_BYTES`, which then no longer opened and
/// locked every secret in it out. The put that would cross the line now fails
/// with `Format`, and the store still opens with what it had.
#[test]
fn a_store_never_grows_past_what_open_accepts() {
    let mk = master("cap");
    let path = store_path("cap");
    let big = SecretBuf::from_vec(vec![0x5a; 6 * 1024 * 1024]).unwrap();
    let mut s = SecretStore::open(&path, &mk).unwrap();
    s.put("big0", &big).unwrap();
    s.put("big1", &big).unwrap();
    assert!(matches!(s.put("big2", &big), Err(Error::Format(_))));
    assert!(!s.contains("big2"));
    drop(s);

    let s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.list("big"), vec!["big0", "big1"]);
    let _ = std::fs::remove_file(&path);
}

/// 0.7.2: one handle per file. A second `open` of the same file while the
/// first handle lives fails with `Io` (`WouldBlock`), instead of the two
/// overwriting each other's writes; once the first is dropped, it opens.
#[test]
fn a_second_open_of_the_same_file_fails_while_the_first_lives() {
    let mk = master("lock");
    let path = store_path("lock");
    let first = SecretStore::open(&path, &mk).unwrap();
    match SecretStore::open(&path, &mk) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
        other => panic!("expected Io(WouldBlock), got {:?}", other.map(|_| ())),
    }
    drop(first);
    SecretStore::open(&path, &mk).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// 0.7.2: the handle `rotate` returns keeps the file's lock.
#[test]
fn rotate_keeps_the_lock() {
    let old_mk = master_with("lock-rot-old", 9);
    let new_mk = master_with("lock-rot-new", 10);
    let path = store_path("lock-rot");
    let rotated = SecretStore::open(&path, &old_mk)
        .unwrap()
        .rotate(&new_mk)
        .unwrap();
    assert!(matches!(
        SecretStore::open(&path, &new_mk),
        Err(Error::Io(_))
    ));
    drop(rotated);
    SecretStore::open(&path, &new_mk).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// 0.7.2: two threads that each open, put and drop the same file lose
/// nothing: a thread waits for its turn instead of overwriting the other.
#[test]
fn two_threads_writing_the_same_file_lose_nothing() {
    let path = store_path("lock-threads");
    let writer = |prefix: &'static str, path: std::path::PathBuf| {
        std::thread::spawn(move || {
            let mk = master(prefix);
            for i in 0..20 {
                loop {
                    match SecretStore::open(&path, &mk) {
                        Ok(mut s) => {
                            let v = SecretBuf::from_vec(vec![b'v'; 64]).unwrap();
                            s.put(&format!("{prefix}{i}"), &v).unwrap();
                            break;
                        }
                        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::yield_now()
                        }
                        Err(e) => panic!("open failed: {e}"),
                    }
                }
            }
        })
    };
    let a = writer("a", path.clone());
    let b = writer("b", path.clone());
    a.join().unwrap();
    b.join().unwrap();

    let mk = master("check");
    let s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.list("a").len(), 20);
    assert_eq!(s.list("b").len(), 20);
    let _ = std::fs::remove_file(&path);
}

/// 0.7.2: the lock file is private, and it stays after the handle is gone;
/// the kernel lock goes away with the handle, so the file never blocks.
#[cfg(unix)]
#[test]
fn the_lock_file_is_private_and_never_goes_stale() {
    let mk = master("lockfile");
    let dir = store_dir("lockfile");
    let path = dir.join("store");
    drop(SecretStore::open(&path, &mk).unwrap());
    let lock = dir.join(".store.lock");
    assert_eq!(mode_of(&lock), 0o600);
    SecretStore::open(&path, &mk).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// (0.8.0) Files made once by an earlier build, with the master key 0..32: a
/// blob for each algorithm and a store. They must open for as long as the
/// format is frozen.
#[test]
fn files_made_once_still_open() {
    let mk = MasterKey::from_bytes(SecretBuf::from_vec((0u8..32).collect()).unwrap()).unwrap();
    let key = mk.derive(b"ctx/v1", b"s").unwrap();
    let fixture = |name: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    };
    for alg in ["aegis256", "xchacha20", "aes256gcm"] {
        let blob = std::fs::read(fixture(&format!("rust-blob-{alg}.bin"))).unwrap();
        assert_eq!(
            krypto::blob_key_id(&blob).unwrap(),
            mk.key_id().unwrap(),
            "{alg}"
        );
        krypto::open(&key, &blob)
            .unwrap()
            .expose(|b| assert_eq!(b, b"value from rust", "{alg}"));
    }
    // A copy, so the lock file and the 0600 on open stay out of the fixtures.
    let dir = store_dir("frozen");
    std::fs::copy(fixture("rust.store"), dir.join("rust.store")).unwrap();
    let store = SecretStore::open(dir.join("rust.store"), &mk).unwrap();
    assert_eq!(store.version(), 1, "rust.store is the frozen v1 fixture");
    assert_eq!(store.counter(), 0, "a v1 file has no counter");
    assert_eq!(store.list(""), ["from-rust"]);
    store
        .get("from-rust")
        .unwrap()
        .expose(|b| assert_eq!(b, b"value from rust"));
    drop(store);
    // The v2 fixture, made once by this code with the same master key (0.9.0).
    std::fs::copy(fixture("rust-v2.store"), dir.join("rust-v2.store")).unwrap();
    let store = SecretStore::open(dir.join("rust-v2.store"), &mk).unwrap();
    assert_eq!(store.version(), 2);
    assert_eq!(store.list(""), ["from-rust"]);
    store
        .get("from-rust")
        .unwrap()
        .expose(|b| assert_eq!(b, b"value from rust"));
    drop(store);
    // A wrong master key is Auth at `open` on a v2 file, even with entries.
    let wrong = MasterKey::from_bytes(SecretBuf::from_vec(vec![7u8; 32]).unwrap()).unwrap();
    assert!(matches!(
        SecretStore::open(dir.join("rust-v2.store"), &wrong),
        Err(Error::Auth)
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- what is at the paths (0.8.2) ---

#[cfg(unix)]
fn set_mode(p: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Make a FIFO at `p` with `mode`.
#[cfg(unix)]
fn make_fifo(p: &std::path::Path, mode: u32) {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    set_mode(p, mode);
}

/// Run `SecretStore::open(path)` in a thread and wait at most 10 s for it, so
/// an `open` that blocks on the FIFO `fifo` fails the test instead of hanging
/// the suite. On timeout the FIFO is opened for writing, which lets the
/// blocked `open` go, and the test fails.
#[cfg(unix)]
fn open_within_time_limit(
    tag: &str,
    path: &std::path::Path,
    fifo: &std::path::Path,
) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let (tx, rx) = std::sync::mpsc::channel();
    let (tag, opened) = (tag.to_string(), path.to_path_buf());
    std::thread::spawn(move || {
        let mk = master(&tag);
        let _ = tx.send(SecretStore::open(&opened, &mk).map(|_| ()));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(outcome) => outcome,
        Err(_) => {
            set_mode(fifo, 0o600);
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo);
            panic!("open blocked on the FIFO {}", fifo.display());
        }
    }
}

/// (0.8.2) A symbolic link at the lock file's name is an error. It is not
/// followed: nothing is made where it points, also when it points into a
/// directory the process cannot write to, which before gave a store without
/// a lock. A FIFO at the lock file's name is an error too, at once; with mode
/// 0400 the read-only open used to wait for a writer.
#[cfg(unix)]
#[test]
fn a_symlink_or_a_fifo_at_the_lock_name_is_an_error() {
    let mk = master("locklink");
    let dir = store_dir("locklink");
    let closed = dir.join("closed");
    std::fs::create_dir(&closed).unwrap();
    set_mode(&closed, 0o500);

    for (store, target) in [
        ("dangling", dir.join("missing-target")),
        ("into-closed", closed.join("lock")),
    ] {
        let lock = dir.join(format!(".{store}.lock"));
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        match SecretStore::open(dir.join(store), &mk) {
            Err(Error::Io(e)) => assert!(
                e.to_string().contains("symbolic link"),
                "{store}: unexpected error: {e}"
            ),
            other => panic!("{store}: expected Io, got {:?}", other.map(|_| ())),
        }
        assert!(
            std::fs::symlink_metadata(&target).is_err(),
            "{store}: something was made at the link's target"
        );
        assert!(
            std::fs::symlink_metadata(dir.join(store)).is_err(),
            "{store}: a store file was made"
        );
    }

    let fifo = dir.join(".fifo.lock");
    make_fifo(&fifo, 0o400);
    match open_within_time_limit("lockfifo", &dir.join("fifo"), &fifo) {
        Err(Error::Io(e)) => assert!(
            e.to_string().contains("not a regular file"),
            "fifo: unexpected error: {e}"
        ),
        other => panic!("fifo: expected Io, got {other:?}"),
    }
    assert!(
        std::fs::symlink_metadata(dir.join("fifo")).is_err(),
        "fifo: a store file was made"
    );

    set_mode(&closed, 0o700);
    let _ = std::fs::remove_dir_all(&dir);
}

/// (0.8.2) A symbolic link at the store path is still read through, but a
/// file that is not a store gives `Format` and keeps its mode: 0600 comes only
/// after the file has been read as a store.
#[cfg(unix)]
#[test]
fn a_symlink_at_the_store_path_to_a_file_that_is_not_a_store_keeps_its_mode() {
    let mk = master("storelink");
    let dir = store_dir("storelink");
    let victim = dir.join("victim.conf");
    std::fs::write(&victim, b"important = true\n").unwrap();
    set_mode(&victim, 0o644);
    std::os::unix::fs::symlink(&victim, dir.join("store")).unwrap();

    assert!(matches!(
        SecretStore::open(dir.join("store"), &mk),
        Err(Error::Format(_))
    ));
    assert_eq!(mode_of(&victim), 0o644);
    assert_eq!(std::fs::read(&victim).unwrap(), b"important = true\n");
    let _ = std::fs::remove_dir_all(&dir);
}

/// (0.8.2) A FIFO at the store path gives `Format` at once; before, `open`
/// waited for a writer that never came. The `open` runs in a thread with a
/// time limit, so a regression fails the test instead of hanging the suite.
#[cfg(unix)]
#[test]
fn a_fifo_at_the_store_path_is_an_error_not_a_hang() {
    let dir = store_dir("fifo");
    let path = dir.join("store");
    make_fifo(&path, 0o600);
    let outcome = open_within_time_limit("fifo", &path, &path);
    assert!(matches!(outcome, Err(Error::Format(_))), "{outcome:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// (0.8.2) The directory is opened before the rename. In a directory that can
/// be written and searched but not read (0300), opening it fails; before, that
/// came after the rename, so `put` reported an error and rolled back in
/// memory while the file already held the new value. Now `put` fails with the
/// file unchanged, and the handle still returns the old value. Root reads any
/// directory, so the test is skipped as root.
#[cfg(unix)]
#[test]
fn put_fails_before_the_rename_when_the_directory_cannot_be_opened() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root can open any directory");
        return;
    }
    let mk = master("dirread");
    let dir = store_dir("dirread");
    let path = dir.join("store");
    let mut s = SecretStore::open(&path, &mk).unwrap();
    s.put(
        "alpha",
        &SecretBuf::from_vec(b"first value".to_vec()).unwrap(),
    )
    .unwrap();
    let before = std::fs::read(&path).unwrap();

    set_mode(&dir, 0o300);
    let result = s.put(
        "alpha",
        &SecretBuf::from_vec(b"second value".to_vec()).unwrap(),
    );
    let after = std::fs::read(&path).unwrap();
    set_mode(&dir, 0o700);

    match result {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
        other => panic!("expected Io(PermissionDenied), got {other:?}"),
    }
    assert_eq!(after, before, "the store file changed");
    s.get("alpha")
        .unwrap()
        .expose(|b| assert_eq!(b, b"first value"));
    let left: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with(".tmp-"))
        .collect();
    assert!(left.is_empty(), "tmp files left behind: {left:?}");
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

// --- store file format v2 (0.9.0) -------------------------------------------
//
// v2 header, 109 bytes: magic "FST1"(4) | ver=2(1) | salt(16) @5 | key_id(16)
// @21 | key_check(32) @37 | counter u64LE(8) @69 | container_mac(32) @77 |
// entries @109 in the identical v1 encoding.

/// A valid v2 store file made by this build, with `names` as entries holding
/// equal-length values (so entries can be swapped byte-for-byte).
fn v2_store_bytes(tag: &str, names: &[&str]) -> (std::path::PathBuf, MasterKey, Vec<u8>) {
    let mk = master(tag);
    let path = store_path(tag);
    {
        let mut s = SecretStore::open(&path, &mk).unwrap();
        assert_eq!(s.version(), 2);
        for (i, n) in names.iter().enumerate() {
            let v = SecretBuf::from_vec(format!("value-{i:02}").into_bytes()).unwrap();
            s.put(n, &v).unwrap();
        }
    }
    let bytes = std::fs::read(&path).unwrap();
    (path, master(tag), bytes)
}

/// The byte ranges of the entries in a v2 store file (entries start at 109).
fn v2_entry_ranges(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut off = 109;
    let mut out = Vec::new();
    while off < bytes.len() {
        let nlen = u16::from_le_bytes([bytes[off], bytes[off + 1]]) as usize;
        let blen_off = off + 2 + nlen;
        let blen = u32::from_le_bytes(bytes[blen_off..blen_off + 4].try_into().unwrap()) as usize;
        let end = blen_off + 4 + blen;
        out.push((off, end));
        off = end;
    }
    out
}

#[test]
fn a_new_store_made_by_open_is_version_2() {
    let mk = master("v2new");
    let path = store_path("v2new");
    let s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.version(), 2);
    assert_eq!(s.counter(), 0, "a new v2 store starts at counter 0");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[0..4], b"FST1");
    assert_eq!(bytes[4], 2);
    assert_eq!(bytes.len(), 109, "an empty v2 store is exactly its header");
    drop(s);
    // And it reopens as v2.
    let s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.version(), 2);
    assert_eq!(s.counter(), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn open_with_version_1_creates_a_v1_store_and_put_keeps_it_v1() {
    let mk = master("v1sticky");
    let path = store_path("v1sticky");
    let mut s = SecretStore::open_with_version(&path, &mk, 1).unwrap();
    assert_eq!(s.version(), 1);
    assert_eq!(s.counter(), 0, "a v1 file has no counter");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes[4], 1);
    assert_eq!(bytes.len(), 37, "an empty v1 store is exactly its header");
    s.put("k", &SecretBuf::from_vec(b"v".to_vec()).unwrap())
        .unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap()[4],
        1,
        "put keeps the file v1 (sticky version)"
    );
    drop(s);
    // Reopening the existing file keeps v1, however it is asked for.
    assert_eq!(SecretStore::open(&path, &mk).unwrap().version(), 1);
    assert_eq!(
        SecretStore::open_with_version(&path, &mk, 2).unwrap().version(),
        1
    );
    // Anything but 1 or 2 is Format, whether or not the file exists.
    assert!(matches!(
        SecretStore::open_with_version(&path, &mk, 3),
        Err(Error::Format(_))
    ));
    let other = store_path("v1sticky-bad");
    assert!(matches!(
        SecretStore::open_with_version(&other, &mk, 0),
        Err(Error::Format(_))
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upgrade_v1_to_v2_keeps_everything_readable_and_is_one_way() {
    let mk = master("upg");
    let path = store_path("upg");
    let mut s = SecretStore::open_with_version(&path, &mk, 1).unwrap();
    s.put("a", &SecretBuf::from_vec(b"first".to_vec()).unwrap())
        .unwrap();
    s.put("b/c", &SecretBuf::from_vec(b"second".to_vec()).unwrap())
        .unwrap();
    let v1_bytes = std::fs::read(&path).unwrap();
    assert_eq!(v1_bytes[4], 1);
    drop(s);

    let s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.version(), 1);
    let s = s.upgrade().unwrap();
    assert_eq!(s.version(), 2);
    assert_eq!(s.counter(), 0);
    s.get("a").unwrap().expose(|b| assert_eq!(b, b"first"));
    s.get("b/c").unwrap().expose(|b| assert_eq!(b, b"second"));
    assert_eq!(s.list(""), ["a", "b/c"]);
    let v2_bytes = std::fs::read(&path).unwrap();
    assert_eq!(v2_bytes[4], 2);
    // Re-wrap only, no re-encryption: the entry table is byte-identical and
    // the file grows by exactly the 72 extra header bytes (109 - 37).
    assert_eq!(&v2_bytes[109..], &v1_bytes[37..]);
    assert_eq!(v2_bytes.len(), v1_bytes.len() + 72);
    drop(s);

    // One-way: reopening the file — even asking for v1 — keeps it v2.
    let s = SecretStore::open_with_version(&path, &mk, 1).unwrap();
    assert_eq!(s.version(), 2);
    assert_eq!(std::fs::read(&path).unwrap()[4], 2);
    s.get("a").unwrap().expose(|b| assert_eq!(b, b"first"));
    drop(s);
    // Upgrading a store that is already v2 is a no-op.
    let s = SecretStore::open(&path, &mk).unwrap();
    let s = s.upgrade().unwrap();
    assert_eq!(s.version(), 2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upgrade_with_the_wrong_master_leaves_the_file_untouched() {
    let mk = master_with("upg-fc", 9);
    let wrong = master_with("upg-fc-wrong", 11);
    let path = store_path("upgrade-failclosed");
    {
        let mut s = SecretStore::open_with_version(&path, &mk, 1).unwrap();
        s.put("a", &SecretBuf::from_vec(b"keep me".to_vec()).unwrap())
            .unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    // v1 `open` does not check the master key, but upgrade decrypts and
    // verifies every entry first, so the wrong master aborts with Auth and
    // nothing is written.
    let stale = SecretStore::open_with_version(&path, &wrong, 1).unwrap();
    assert!(matches!(stale.upgrade(), Err(Error::Auth)));
    assert_eq!(std::fs::read(&path).unwrap(), before, "file untouched");
    assert_eq!(std::fs::read(&path).unwrap()[4], 1);
    // The real master still reads it.
    let s = SecretStore::open(&path, &mk).unwrap();
    s.get("a").unwrap().expose(|b| assert_eq!(b, b"keep me"));
    let _ = std::fs::remove_file(&path);
}

/// Tampering with the entry table of a v2 file is Auth at `open`: the
/// container MAC covers header[0..77] || entries as one unit.
#[test]
fn a_flipped_byte_in_a_v2_entry_gives_auth_at_open() {
    let (path, mk, mut bytes) = v2_store_bytes("tamper-flip", &["aa"]);
    let (start, end) = v2_entry_ranges(&bytes)[0];
    let _ = start;
    bytes[end - 1] ^= 0xff; // last byte of the blob (the AEAD tag)
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(SecretStore::open(&path, &mk), Err(Error::Auth)));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_deleted_entry_in_a_v2_store_gives_auth_at_open() {
    let (path, mk, bytes) = v2_store_bytes("tamper-del", &["aa", "bb"]);
    let r = v2_entry_ranges(&bytes);
    let mut out = bytes[..r[0].0].to_vec();
    out.extend_from_slice(&bytes[r[1].0..]); // drop the first entry entirely
    std::fs::write(&path, &out).unwrap();
    assert!(matches!(SecretStore::open(&path, &mk), Err(Error::Auth)));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn two_swapped_entries_in_a_v2_store_give_auth_at_open() {
    // Equal-length names and values, so the swapped file still parses — it is
    // the container MAC that catches the reordering.
    let (path, mk, mut bytes) = v2_store_bytes("tamper-swap", &["aa", "bb"]);
    let r = v2_entry_ranges(&bytes);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].1 - r[0].0, r[1].1 - r[1].0, "entries must be same-sized");
    let e0 = bytes[r[0].0..r[0].1].to_vec();
    let e1 = bytes[r[1].0..r[1].1].to_vec();
    bytes[r[0].0..r[0].1].copy_from_slice(&e1);
    bytes[r[1].0..r[1].1].copy_from_slice(&e0);
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(SecretStore::open(&path, &mk), Err(Error::Auth)));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_injected_entry_in_a_v2_store_gives_auth_at_open() {
    let (path, mk, mut bytes) = v2_store_bytes("tamper-inject", &["aa"]);
    // Append a well-formed entry with a garbage blob: the structure is valid,
    // so the container MAC is what rejects it (a name must not be injectable
    // into list()).
    let mut entry = Vec::new();
    entry.extend_from_slice(&5u16.to_le_bytes());
    entry.extend_from_slice(b"evil!");
    entry.extend_from_slice(&32u32.to_le_bytes());
    entry.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&entry);
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(SecretStore::open(&path, &mk), Err(Error::Auth)));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_truncated_v2_store_gives_auth_at_open() {
    // Cut the file back to just the 109-byte header: the entry table is then
    // empty but still well-formed, so it is the container MAC that fails.
    // (A cut inside an entry is a structure error — Format — which the spec
    // checks before the MACs.)
    let (path, mk, bytes) = v2_store_bytes("tamper-trunc", &["aa", "bb"]);
    std::fs::write(&path, &bytes[..109]).unwrap();
    assert!(matches!(SecretStore::open(&path, &mk), Err(Error::Auth)));
    let _ = std::fs::remove_file(&path);
}

/// Any flipped byte in the v2-only header fields is Auth at `open`: the
/// key_check covers the salt, the container_mac covers the key_id, the
/// counter and the entries, and the MAC field itself is compared.
#[test]
fn a_tampered_v2_header_gives_auth_at_open() {
    let (path, mk, bytes) = v2_store_bytes("tamper-hdr", &["aa"]);
    // salt(5..21), key_id(21..37), key_check(37..69), counter(69..77),
    // container_mac(77..109).
    for offset in [5, 30, 50, 70, 90, 108] {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 0xff;
        std::fs::write(&path, &tampered).unwrap();
        assert!(
            matches!(SecretStore::open(&path, &mk), Err(Error::Auth)),
            "offset {offset}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_wrong_master_key_on_a_v2_store_gives_auth_at_open() {
    let mk = master("v2wrong");
    let wrong = master_with("v2wrong-wrong", 7);
    // An empty v2 store: the key_check alone already rejects the wrong master.
    let path = store_path("v2wrong-empty");
    drop(SecretStore::open(&path, &mk).unwrap());
    assert!(matches!(SecretStore::open(&path, &wrong), Err(Error::Auth)));
    let _ = std::fs::remove_file(&path);

    // A v2 store with entries: same, and the right master still opens it.
    let (path, _mk, _bytes) = v2_store_bytes("v2wrong-full", &["aa"]);
    assert!(matches!(SecretStore::open(&path, &wrong), Err(Error::Auth)));
    let s = SecretStore::open(&path, &mk).unwrap();
    s.get("aa").unwrap().expose(|b| assert_eq!(b, b"value-00"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn open_with_min_counter_detects_a_rolled_back_file() {
    let mk = master("rollback");
    let path = store_path("rollback");
    let mut s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.counter(), 0);
    s.put("a", &SecretBuf::from_vec(b"1".to_vec()).unwrap())
        .unwrap();
    s.put("b", &SecretBuf::from_vec(b"2".to_vec()).unwrap())
        .unwrap();
    assert_eq!(s.counter(), 2);
    drop(s);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[69..77].try_into().unwrap()), 2);

    // Anchored at or below the file's counter: opens.
    assert_eq!(
        SecretStore::open_with_min_counter(&path, &mk, 2).unwrap().counter(),
        2
    );
    assert_eq!(
        SecretStore::open_with_min_counter(&path, &mk, 0).unwrap().counter(),
        2
    );
    // Above it: Rollback, with both counters in the error.
    match SecretStore::open_with_min_counter(&path, &mk, 3) {
        Err(Error::Rollback {
            file_counter,
            min_counter,
        }) => {
            assert_eq!(file_counter, 2);
            assert_eq!(min_counter, 3);
        }
        other => panic!("expected Rollback, got {:?}", other.map(|_| ())),
    }
    // The failed open did not touch the file.
    assert_eq!(std::fs::read(&path).unwrap(), bytes);

    // A v1 file counts as counter 0: any positive anchor is a rollback.
    let v1path = store_path("rollback-v1");
    drop(SecretStore::open_with_version(&v1path, &mk, 1).unwrap());
    match SecretStore::open_with_min_counter(&v1path, &mk, 1) {
        Err(Error::Rollback {
            file_counter,
            min_counter,
        }) => {
            assert_eq!((file_counter, min_counter), (0, 1));
        }
        other => panic!("expected Rollback, got {:?}", other.map(|_| ())),
    }
    SecretStore::open_with_min_counter(&v1path, &mk, 0).unwrap();

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&v1path);
}

#[test]
fn the_v2_counter_increases_on_every_write() {
    let mk = master("counter");
    let path = store_path("counter");
    let mut s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.counter(), 0, "a new v2 store starts at 0");
    let v = SecretBuf::from_vec(b"v".to_vec()).unwrap();
    s.put("a", &v).unwrap();
    assert_eq!(s.counter(), 1);
    s.put("b", &v).unwrap();
    assert_eq!(s.counter(), 2);
    s.delete("a").unwrap();
    assert_eq!(s.counter(), 3);
    drop(s);
    // The counter is in the file, u64 LE at offset 69, and survives a reopen.
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[69..77].try_into().unwrap()), 3);
    assert_eq!(SecretStore::open(&path, &mk).unwrap().counter(), 3);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rotate_on_a_v2_store_keeps_the_version_and_resets_the_counter() {
    let old_mk = master_with("rotv2-old", 9);
    let new_mk = master_with("rotv2-new", 10);
    let path = store_path("rotv2");
    let mut s = SecretStore::open(&path, &old_mk).unwrap();
    assert_eq!(s.version(), 2);
    s.put("a", &SecretBuf::from_vec(b"first".to_vec()).unwrap())
        .unwrap();
    s.put("b", &SecretBuf::from_vec(b"second".to_vec()).unwrap())
        .unwrap();
    assert_eq!(s.counter(), 2);
    let before = std::fs::read(&path).unwrap();

    let r = s.rotate(&new_mk).unwrap();
    assert_eq!(r.version(), 2, "rotation keeps the file version (sticky)");
    assert_eq!(r.counter(), 0, "the new generation starts at counter 0");
    r.get("a").unwrap().expose(|b| assert_eq!(b, b"first"));
    r.get("b").unwrap().expose(|b| assert_eq!(b, b"second"));
    let after = std::fs::read(&path).unwrap();
    assert_eq!(after[4], 2);
    assert_eq!(u64::from_le_bytes(after[69..77].try_into().unwrap()), 0);
    assert_ne!(&after[5..21], &before[5..21], "rotation draws a fresh salt");
    assert_ne!(
        &after[21..37],
        &before[21..37],
        "rotation draws a fresh key id"
    );
    drop(r);

    // Reopens as v2 under the new master, at counter 0; the old master is
    // Auth at open (the key_check no longer matches).
    let s = SecretStore::open(&path, &new_mk).unwrap();
    assert_eq!((s.version(), s.counter()), (2, 0));
    drop(s);
    assert!(matches!(
        SecretStore::open(&path, &old_mk),
        Err(Error::Auth)
    ));
    let _ = std::fs::remove_file(&path);
}

/// The MAX_STORE_BYTES cap covers the whole file, the 109-byte v2 header
/// included: a put that would cross it fails with Format and leaves the file
/// unchanged — where the same content in a v1 file (37-byte header) still fits.
#[test]
fn the_v2_header_counts_toward_max_store_bytes() {
    let mk = master("capv2");
    // Calibrate the AEAD blob overhead: a v1 store with one 1-byte value is
    // 37 + (2 + 1 + 4) + blob(1) bytes, and blob(len) = overhead + len.
    let cal = store_path("capv2-cal");
    {
        let mut s = SecretStore::open_with_version(&cal, &mk, 1).unwrap();
        s.put("a", &SecretBuf::from_vec(vec![0u8; 1]).unwrap())
            .unwrap();
    }
    let blob_overhead = std::fs::read(&cal).unwrap().len() - 37 - 7 - 1;
    let _ = std::fs::remove_file(&cal);

    // One big entry sized so the v2 file lands 36 bytes below the cap. The v2
    // header (109) is exactly 72 bytes longer than the v1 header (37), so the
    // same content in a v1 file leaves room for one more small entry.
    let big_len = krypto::MAX_STORE_BYTES - 109 - (2 + 3 + 4) - blob_overhead - 36;
    let big = SecretBuf::from_vec(vec![0x5a; big_len]).unwrap();
    let small = SecretBuf::from_vec(vec![0u8; 1]).unwrap();

    let path = store_path("capv2");
    let mut s = SecretStore::open(&path, &mk).unwrap();
    s.put("big", &big).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(before.len() <= krypto::MAX_STORE_BYTES);
    assert!(matches!(s.put("x", &small), Err(Error::Format(_))));
    assert!(!s.contains("x"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the file must be unchanged"
    );
    drop(s);
    // The store still opens with what it had.
    let s = SecretStore::open(&path, &mk).unwrap();
    assert_eq!(s.list(""), ["big"]);

    // v1 with the same content: the small put fits, because the header there
    // is only 37 bytes — the difference is exactly the 72 extra v2 bytes.
    let path1 = store_path("capv2-v1");
    let mut s1 = SecretStore::open_with_version(&path1, &mk, 1).unwrap();
    s1.put("big", &big).unwrap();
    s1.put("x", &small).unwrap();
    assert!(std::fs::read(&path1).unwrap().len() <= krypto::MAX_STORE_BYTES);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&path1);
}
