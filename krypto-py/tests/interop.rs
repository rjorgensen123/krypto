// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rust and Python on the same data (0.8.0): what `krypto` makes here,
//! `krypto_py` opens, and the other way round.
//!
//! The live tests run `tests/peer.py` under the Python that `PYO3_PYTHON`
//! names, with `krypto_py` installed (`maturin develop`). Rust writes what it
//! makes to `rust/` in a temp dir; the peer opens and checks it, and writes
//! what Python makes to `python/`, which Rust then opens and checks. Where a
//! function gives one answer for one input, the peer writes its answer too,
//! and it must be Rust's.
//!
//! The files in `tests/fixtures/` were made once by `krypto`, with the master
//! key 0..32, and must open for as long as the format is frozen.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use krypto::password::{self, Preset};
use krypto::{exchange, sign, Alg, DerivedKey, MasterKey, SecretBuf, SecretStore, SecretString};

const CONTEXT: &[u8] = b"interop/v1";
const SALT: &[u8] = b"interop-salt";
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
        krypto::hex::encode(&message).as_bytes()
    );
    assert_eq!(
        dir.read("python/base64"),
        krypto::base64::encode(&message).as_bytes()
    );
}

#[test]
fn files_made_once_still_open() {
    let master = MasterKey::from_bytes(secret(&(0u8..32).collect::<Vec<_>>())).unwrap();
    let key = master.derive(b"ctx/v1", b"s").unwrap();
    let fixture = |name: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    };
    for (name, _) in ALGS {
        let blob = fs::read(fixture(&format!("rust-blob-{name}.bin"))).unwrap();
        assert_eq!(
            krypto::blob_key_id(&blob).unwrap(),
            master.key_id().unwrap(),
            "{name}"
        );
        assert_opens(&key, &blob, b"value from rust", name);
    }
    // A copy, so the lock file and the 0600 on open stay out of the fixtures.
    let dir = Dir::new("frozen");
    fs::copy(fixture("rust.store"), dir.path("rust.store")).unwrap();
    let store = SecretStore::open(dir.path("rust.store"), &master).unwrap();
    assert_eq!(store.list(""), ["from-rust"]);
    store
        .get("from-rust")
        .unwrap()
        .expose(|b| assert_eq!(b, b"value from rust"));
}
