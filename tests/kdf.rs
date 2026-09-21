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

/// `info` and `salt` are bounded, like every other input the crate takes.
///
/// Both reach the API from command lines and config files (`krypto-cli`'s
/// `--context` and `--salt`), and an unbounded one is work whose size an
/// attacker chooses. The cap has room to spare over the longest real use: the
/// store's `krypto/store/v1|` prefix plus a 512-byte key name.
#[test]
fn oversized_info_and_salt_are_rejected() {
    use krypto::MAX_DERIVE_INPUT_BYTES;
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
    assert!(
        mk.derive(&over, b"saltsalt").is_err(),
        "info one byte over the cap was accepted"
    );
    assert!(
        mk.derive(b"krypto/test/v1", &over).is_err(),
        "salt one byte over the cap was accepted"
    );
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

/// Empty `info` must be rejected: it IS the purpose separation in HKDF.
///
/// Without it the audit-MAC key and the token-sealing key would have been
/// **identical** — a failure impossible to spot after the fact, and one a
/// missing config value is enough to trigger.
#[test]
fn empty_info_is_rejected() {
    let mk = test_master("empty-info");
    assert!(
        mk.derive(b"", b"saltsalt").is_err(),
        "empty info was accepted"
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
