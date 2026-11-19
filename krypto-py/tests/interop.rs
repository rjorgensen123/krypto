// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rust and Python on the same data (0.8.0): what `krypto` makes here,
//! `krypto_py` opens, and the other way round.
//!
//! The live tests run `tests/peer.py` under the Python that `PYO3_PYTHON`
//! names, with `krypto_py` installed (`maturin develop`). Rust writes what it
//! makes to `rust/` in a temp dir; the peer opens and checks it, and writes
//! what Python makes to `python/`, which Rust then opens and checks. Where a
//! function gives one answer for one input, the peer writes its answer too,
//! and it must be Rust's. Where Rust works on what Python made, the peer runs
//! a second time to check the result.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use krypto::password::{self, Preset};
use krypto::{
    exchange, sign, Alg, DerivedKey, Error, MasterKey, SecretBuf, SecretStore, SecretString,
};

const CONTEXT: &[u8] = b"interop/v1";
const SALT: &[u8] = b"interop-salt";
const AAD: &[u8] = b"record/42";
const OTHER_AAD: &[u8] = b"record/43";
const NEW_AAD: &[u8] = b"record/44";
const PASSWORD: &str = "correct horse battery staple";
const ALGS: [(&str, Alg); 3] = [
    ("aegis256", Alg::Aegis256),
    ("xchacha20", Alg::XChaCha20Poly1305),
    ("aes256gcm", Alg::Aes256Gcm),
];

/// A temp dir with `rust/` and `python/`, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("krypto-py-interop-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("rust")).unwrap();
        fs::create_dir_all(dir.join("python")).unwrap();
        Dir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, data: &[u8]) {
        fs::write(self.path(name), data).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.path(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs the Python side; its failed checks come back as the panic message.
fn peer(mode: &str, dir: &Dir) {
    let python = std::env::var_os("PYO3_PYTHON").unwrap_or_else(|| "python3".into());
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/peer.py");
    let out = Command::new(&python)
        .arg("-I")
        .arg(&script)
        .arg(mode)
        .arg(&dir.0)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {python:?}: {e}"));
    assert!(
        out.status.success(),
        "the Python side failed ({mode}); PYO3_PYTHON must name a Python with krypto_py \
         installed (maturin develop):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn secret(data: &[u8]) -> SecretBuf {
    SecretBuf::from_vec(data.to_vec()).unwrap()
}

/// A random master key, written to `name` for the peer.
fn random_master(dir: &Dir, name: &str) -> MasterKey {
    let key = SecretBuf::random(32).unwrap();
    key.expose(|b| dir.write(name, b));
    MasterKey::from_bytes(key).unwrap()
}

fn assert_opens(key: &DerivedKey, blob: &[u8], expected: &[u8], what: &str) {
    krypto::open(key, blob)
        .unwrap_or_else(|e| panic!("{what}: {e}"))
        .expose(|b| assert_eq!(b, expected, "{what}"));
}

/// `blob` opens under `key` with `aad`, and is `Auth` with `other_aad`, with
/// an empty AAD and through `open`, which takes none.
fn assert_bound_to_aad(
    key: &DerivedKey,
    blob: &[u8],
    aad: &[u8],
    other_aad: &[u8],
    expected: &[u8],
    what: &str,
) {
    krypto::open_with_aad(key, blob, aad)
        .unwrap_or_else(|e| panic!("{what}: {e}"))
        .expose(|b| assert_eq!(b, expected, "{what}"));
    for wrong in [other_aad, b""] {
        assert!(
            matches!(krypto::open_with_aad(key, blob, wrong), Err(Error::Auth)),
            "{what}: opened with the AAD {wrong:?}, or not as Auth"
        );
    }
    assert!(
        matches!(krypto::open(key, blob), Err(Error::Auth)),
        "{what}: opened without AAD, or not as Auth"
    );
}

/// `path` opened anchored one above the store's counter is `Rollback`, with
/// both counters in the error.
fn assert_rollback(path: &Path, master: &MasterKey, counter: u64) {
    match SecretStore::open_with_min_counter(path, master, counter + 1) {
        Err(Error::Rollback {
            file_counter,
            min_counter,
        }) => assert_eq!((file_counter, min_counter), (counter, counter + 1)),
        other => panic!("expected Rollback, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn what_one_side_encrypts_the_other_opens() {
    let dir = Dir::new("seal");
    let master = random_master(&dir, "master.key");
    let master2 = random_master(&dir, "master2.key");
    let message = krypto::random_bytes(1000).unwrap();
    dir.write("message", &message);
    let key = master.derive(CONTEXT, SALT).unwrap();
    let key2 = master2.derive(CONTEXT, SALT).unwrap();
    let id = master.key_id().unwrap();
    let id2 = master2.key_id().unwrap();

    for (name, alg) in ALGS {
        let blob = krypto::seal(&key, &id, &secret(&message), alg).unwrap();
        dir.write(&format!("rust/blob-{name}"), &blob);
    }
    let blob = dir.read("rust/blob-aegis256");
    dir.write(
        "rust/resealed",
        &krypto::reseal(&key, &key2, &id2, &blob).unwrap(),
    );
    {
        let mut store = SecretStore::open(dir.path("shared.store"), &master).unwrap();
        store.put("from-rust", &secret(&message)).unwrap();
    } // the handle goes, and its lock with it

    peer("seal", &dir);

    for (name, _) in ALGS {
        let blob = dir.read(&format!("python/blob-{name}"));
        assert_eq!(krypto::blob_key_id(&blob).unwrap(), id, "{name}");
        assert_opens(&key, &blob, &message, name);
    }
    assert_opens(&key2, &dir.read("python/resealed"), &message, "resealed");
    assert_eq!(dir.read("python/key-id"), id);
    assert_eq!(
        dir.read("python/hmac"),
        krypto::hmac_sha256(&key, &message).unwrap()
    );
    let store = SecretStore::open(dir.path("shared.store"), &master).unwrap();
    assert_eq!(store.list(""), ["from-python", "from-rust"]);
    store
        .get("from-python")
        .unwrap()
        .expose(|b| assert_eq!(b, message));
}

#[test]
fn passwords_signatures_and_key_agreement_cross_both_ways() {
    let dir = Dir::new("keys");
    let message = krypto::random_bytes(1000).unwrap();
    dir.write("message", &message);
    let pw = SecretString::from_string(PASSWORD.into()).unwrap();
    let pw_salt = krypto::random_bytes(16).unwrap();
    dir.write("pw-salt", &pw_salt);

    dir.write(
        "rust/phc",
        password::hash(&pw, Preset::Interactive).unwrap().as_bytes(),
    );
    let (ed_seed, ed_public) = sign::ed25519_keypair().unwrap();
    ed_seed.expose(|b| dir.write("rust/ed25519.seed", b));
    dir.write("rust/ed25519.public", &ed_public);
    let ed_sig = sign::ed25519_sign(&ed_seed, &message).unwrap();
    dir.write("rust/ed25519.sig", &ed_sig);
    let (pkcs8, p256_public) = sign::ecdsa_p256_keypair().unwrap();
    pkcs8.expose(|b| dir.write("rust/p256.pkcs8", b));
    dir.write("rust/p256.public", &p256_public);
    dir.write(
        "rust/p256.sig",
        &sign::ecdsa_p256_sign(&pkcs8, &message).unwrap(),
    );
    let (x_secret, x_public) = exchange::x25519_keypair().unwrap();
    dir.write("rust/x25519.public", &x_public);

    peer("keys", &dir);

    // What Python made, Rust accepts.
    password::verify(&pw, std::str::from_utf8(&dir.read("python/phc")).unwrap()).unwrap();
    sign::ed25519_verify(
        &dir.read("python/ed25519.public"),
        &message,
        &dir.read("python/ed25519.sig"),
    )
    .unwrap();
    sign::ecdsa_p256_verify(
        &dir.read("python/p256.public"),
        &message,
        &dir.read("python/p256.sig"),
    )
    .unwrap();
    exchange::x25519_shared(&x_secret, &dir.read("python/x25519.public"))
        .unwrap()
        .expose(|s| assert_eq!(s, dir.read("python/x25519.shared"), "x25519"));

    // Where the input fixes the answer, Python gives Rust's.
    password::derive_key(&pw, &pw_salt, Preset::Interactive)
        .unwrap()
        .expose(|k| assert_eq!(k, dir.read("python/derived-key"), "derive_key"));
    assert_eq!(dir.read("python/ed25519.public-of-rust"), ed_public);
    assert_eq!(dir.read("python/ed25519.sig-of-rust"), ed_sig);
    assert_eq!(dir.read("python/p256.public-of-rust"), p256_public);
    assert_eq!(dir.read("python/sha256"), krypto::sha256(&message));
    assert_eq!(
        dir.read("python/hex"),
        krypto::hex::encode(&message).unwrap().as_bytes()
    );
    assert_eq!(
        dir.read("python/base64"),
        krypto::base64::encode(&message).unwrap().as_bytes()
    );
}

#[test]
fn aad_binds_the_blobs_of_both_sides() {
    let dir = Dir::new("aad");
    let master = random_master(&dir, "master.key");
    let master2 = random_master(&dir, "master2.key");
    let message = krypto::random_bytes(1000).unwrap();
    dir.write("message", &message);
    let key = master.derive(CONTEXT, SALT).unwrap();
    let key2 = master2.derive(CONTEXT, SALT).unwrap();
    let id = master.key_id().unwrap();
    let id2 = master2.key_id().unwrap();

    for (name, alg) in ALGS {
        let blob = krypto::seal_with_aad(&key, &id, &secret(&message), alg, AAD).unwrap();
        dir.write(&format!("rust/aad-blob-{name}"), &blob);
    }
    let blob = dir.read("rust/aad-blob-aegis256");
    dir.write(
        "rust/aad-resealed",
        &krypto::reseal_with_aad(&key, &key2, &id2, &blob, AAD, NEW_AAD).unwrap(),
    );

    peer("aad", &dir);

    for (name, _) in ALGS {
        let blob = dir.read(&format!("python/aad-blob-{name}"));
        assert_eq!(krypto::blob_key_id(&blob).unwrap(), id, "{name}");
        assert_bound_to_aad(&key, &blob, AAD, OTHER_AAD, &message, name);
    }
    // Python resealed the blob Rust sealed with AAD.
    assert_bound_to_aad(
        &key2,
        &dir.read("python/aad-resealed"),
        NEW_AAD,
        AAD,
        &message,
        "resealed",
    );

    // Rust reseals the blob Python sealed with AAD, and Python opens it.
    let blob = dir.read("python/aad-blob-aegis256");
    let resealed = krypto::reseal_with_aad(&key, &key2, &id2, &blob, AAD, NEW_AAD).unwrap();
    assert_bound_to_aad(&key2, &resealed, NEW_AAD, AAD, &message, "resealed by Rust");
    dir.write("rust/aad-resealed-of-python", &resealed);

    peer("aad-back", &dir);
}

/// A new store is version 2 at counter 0, every write adds one, and the other
/// side sees that counter: an open anchored at it succeeds, one above it is
/// `Rollback`.
#[test]
fn a_version_2_store_crosses_both_ways() {
    let dir = Dir::new("store-v2");
    let master = random_master(&dir, "master.key");
    let message = krypto::random_bytes(1000).unwrap();
    dir.write("message", &message);
    {
        let mut store = SecretStore::open(dir.path("rust.store"), &master).unwrap();
        assert_eq!((store.version(), store.counter()), (2, 0), "a new store");
        store.put("from-rust", &secret(&message)).unwrap();
        assert_eq!(store.counter(), 1, "after one write");
    }

    peer("store-v2", &dir);

    // Rust's store, after Python wrote to it.
    let store = SecretStore::open_with_version(dir.path("rust.store"), &master, 2).unwrap();
    assert_eq!(store.counter(), 2, "rust.store after Python's write");
    assert_eq!(store.list(""), ["from-python", "from-rust"]);
    store
        .get("from-python")
        .unwrap()
        .expose(|b| assert_eq!(b, message));
    drop(store);

    // The store Python made and wrote once.
    let path = dir.path("python.store");
    assert_rollback(&path, &master, 1);
    {
        let mut store = SecretStore::open_with_min_counter(&path, &master, 1).unwrap();
        assert_eq!((store.version(), store.counter()), (2, 1), "python.store");
        store
            .get("from-python")
            .unwrap()
            .expose(|b| assert_eq!(b, message));
        store.put("from-rust", &secret(&message)).unwrap();
        assert_eq!(store.counter(), 2, "python.store after Rust's write");
    }

    peer("store-v2-back", &dir);
}

/// A version 1 store made by one side and upgraded by the other is version 2
/// at counter 0 and reads on the first side; a store rotated by one side opens
/// on the other under the new master key, at counter 0, and is `WrongKey`
/// under the old one.
#[test]
fn upgrade_and_rotate_cross_both_ways() {
    let dir = Dir::new("upgrade-rotate");
    let master = random_master(&dir, "master.key");
    let master2 = random_master(&dir, "master2.key");
    let message = krypto::random_bytes(1000).unwrap();
    dir.write("message", &message);
    {
        let mut store =
            SecretStore::open_with_version(dir.path("rust-v1.store"), &master, 1).unwrap();
        store.put("from-rust", &secret(&message)).unwrap();
        assert_eq!((store.version(), store.counter()), (1, 0), "a v1 store");
    }
    {
        let mut store = SecretStore::open(dir.path("rust-rotated.store"), &master).unwrap();
        store.put("from-rust", &secret(&message)).unwrap();
        let store = store.rotate(&master2).unwrap();
        assert_eq!((store.version(), store.counter()), (2, 0), "after rotate");
    }

    peer("upgrade-rotate", &dir);

    // Rust's v1 store, upgraded by Python.
    let store = SecretStore::open_with_version(dir.path("rust-v1.store"), &master, 2).unwrap();
    assert_eq!(store.counter(), 0, "rust-v1.store after Python's upgrade");
    store
        .get("from-rust")
        .unwrap()
        .expose(|b| assert_eq!(b, message));
    drop(store);

    // The store Python rotated.
    let path = dir.path("python-rotated.store");
    assert!(
        matches!(SecretStore::open(&path, &master), Err(Error::WrongKey)),
        "the store Python rotated opened under the old master key, or not as WrongKey"
    );
    let store = SecretStore::open(&path, &master2).unwrap();
    assert_eq!(
        (store.version(), store.counter()),
        (2, 0),
        "python-rotated.store"
    );
    store
        .get("from-python")
        .unwrap()
        .expose(|b| assert_eq!(b, message));
    drop(store);

    // The v1 store Python made, upgraded here.
    let store = SecretStore::open_with_version(dir.path("python-v1.store"), &master, 1)
        .unwrap()
        .upgrade()
        .unwrap();
    assert_eq!((store.version(), store.counter()), (2, 0), "after upgrade");
    drop(store);

    peer("upgrade-rotate-back", &dir);
}
