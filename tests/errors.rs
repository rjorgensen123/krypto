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
    let anchored = dir.join("anchored.store");
    drop(SecretStore::open(&anchored, &m).unwrap());
    // `err()`: a SecretStore has no Debug either.
    let rollback = SecretStore::open_with_min_counter(&anchored, &m, 1)
        .err()
        .unwrap();

    let cases: [(Error, &str); 7] = [
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
        // The opens of a v2 store file return it when the master key does not
        // fit; built directly here.
        (Error::WrongKey, "the key does not fit"),
        (rollback, "rollback detected"),
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

/// `hex` and `base64` decoding (0.8.2): the message about an invalid character
/// names neither the character nor its position, since the input may be a key.
/// Each probe is the invalid character as the input has it, or as a message
/// could show its byte (`Ã` for the first byte of `é`, `\u{1b}` for ESC), and
/// none of them occurs in the fixed message text.
#[test]
fn decode_errors_show_nothing_of_the_input() {
    use krypto::{base64, hex};
    const HEX: &str = "invalid hex character";
    const B64: &str = "invalid base64 character";

    let cases: [(Error, &str, &[&str]); 7] = [
        (hex::decode("ab12CDef").unwrap_err(), HEX, &["C"]),
        (hex::decode("abé").unwrap_err(), HEX, &["é", "Ã"]),
        (
            hex::decode("ab\u{1b}[31mx").unwrap_err(),
            HEX,
            &["\u{1b}", "\\u{1b}"],
        ),
        (
            base64::decode("Zm9\nYmFy").unwrap_err(),
            B64,
            &["\n", "\\n"],
        ),
        (base64::decode("Zm-vYmFy").unwrap_err(), B64, &["-"]),
        (base64::decode_nopad("Zm_v").unwrap_err(), B64, &["_"]),
        (base64::decode("Zm=vYmFy").unwrap_err(), B64, &["="]),
    ];

    let mut texts = std::collections::BTreeSet::new();
    for (e, says, probes) in cases {
        assert!(matches!(e, Error::Format(_)), "{e:?} should be Format");
        let msg = e.to_string();
        assert!(msg.contains(says), "{msg:?} should say {says:?}");
        for probe in probes {
            assert!(!msg.contains(probe), "{msg:?} shows {probe:?}");
        }
        texts.insert(msg);
    }
    // One text per decoder, wherever the invalid character is (index 2 to 4).
    assert_eq!(texts.len(), 2, "{texts:?}");
}
