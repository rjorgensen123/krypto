// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error messages (0.8.0): each kind says what went wrong, and none carries
//! key material or plaintext. `krypto-py` raises them with the same text.

use krypto::{Alg, Error, MasterKey, SecretBuf, SecretStore};

const PLAINTEXT: &str = "plaintext that must never show";

fn master(byte: u8) -> MasterKey {
    MasterKey::from_bytes(SecretBuf::from_vec(vec![byte; 32]).unwrap()).unwrap()
}

#[test]
fn every_error_says_what_went_wrong_and_nothing_secret() {
    let m = master(0x5a);
    let key = m.derive(b"ctx/v1", b"salt").unwrap();
    let secret = SecretBuf::from_vec(PLAINTEXT.as_bytes().to_vec()).unwrap();
    let blob = krypto::seal(&key, &m.key_id().unwrap(), &secret, Alg::Aegis256).unwrap();
    let other = master(0xa5).derive(b"ctx/v1", b"salt").unwrap();
    let dir = std::env::temp_dir().join(format!("krypto-errors-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = SecretStore::open(dir.join("s.store"), &m).unwrap();

    let cases: [(Error, &str); 6] = [
        (
            krypto::open(&other, &blob).unwrap_err(),
            "authentication failure",
        ),
        (
            krypto::open(&key, b"not a blob").unwrap_err(),
            "format error",
        ),
        (
            // `err()`: a MasterKey has no Debug, on purpose.
            MasterKey::from_secret_file(dir.join("no-such-key"))
                .err()
                .unwrap(),
            "i/o error",
        ),
        (
            krypto::random_bytes_with_limit(usize::MAX, usize::MAX).unwrap_err(),
            "hardening error",
        ),
        (store.get("no-such-name").unwrap_err(), "not found"),
        // No library function returns it since 0.7.3, but it is still a variant.
        (Error::WrongKey, "different key generation"),
    ];
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();

    for (e, says) in cases {
        let msg = e.to_string();
        assert!(msg.contains(says), "{msg:?} should say {says:?}");
        assert!(
            !msg.contains(PLAINTEXT) && !msg.to_lowercase().contains("5a5a5a5a"),
            "{msg:?} carries a secret"
        );
    }
}
