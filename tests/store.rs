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
    s.put("device/pe1/ssh-key", &secret).unwrap();
    let out = s.get("device/pe1/ssh-key").unwrap();
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

fn valid_store_bytes(tag: &str) -> (std::path::PathBuf, MasterKey, Vec<u8>) {
    let mk = master(tag);
    let path = store_path(tag);
    {
        let mut s = SecretStore::open(&path, &mk).unwrap();
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
    // Change the name a blob sits under → open must give Auth (per-name DEK).
    let mk = master("bind");
    let path = store_path("bind");
    {
        let mut s = SecretStore::open(&path, &mk).unwrap();
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

/// A blob from a different key generation is `WrongKey` — routing, not tampering.
///
/// Before 0.5.0 this surfaced as `Auth`, which `krypto-cli` maps to "should be
/// alarmed" — a false security alarm for a perfectly normal old-generation
/// blob.
#[test]
fn different_key_generation_gives_wrongkey_not_auth() {
    let mk = master("gen");
    let path = store_path("gen");
    {
        let mut s = SecretStore::open(&path, &mk).unwrap();
        s.put("a", &SecretBuf::from_vec(b"value".to_vec()).unwrap())
            .unwrap();
    }
    // Flip a byte in the STORE header's key_id (offset 5+16=21): the store now
    // claims a different generation than the blob was sealed under.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[21] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let mk2 = master("gen");
    let s = SecretStore::open(&path, &mk2).unwrap();
    assert!(matches!(s.get("a"), Err(Error::WrongKey)));
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

    // Reopening the FILE with the new master works; with the old master the
    // per-name DEKs no longer match → Auth on get (the file is one generation).
    let reopened = SecretStore::open(&path, &new_mk).unwrap();
    reopened
        .get("b")
        .unwrap()
        .expose(|b| assert_eq!(b, b"second"));
    let stale = SecretStore::open(&path, &old_mk).unwrap();
    assert!(matches!(stale.get("a"), Err(Error::Auth)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn rotate_with_the_wrong_master_leaves_the_file_untouched() {
    let mk = master_with("rot-fc", 9);
    let wrong = master_with("rot-fc-wrong", 11);
    let path = store_path("rotate-failclosed");

    let mut store = SecretStore::open(&path, &mk).unwrap();
    store
        .put("a", &SecretBuf::from_vec(b"keep me".to_vec()).unwrap())
        .unwrap();

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
