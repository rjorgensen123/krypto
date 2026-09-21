// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for argon2id password hashing.

use krypto::password::{self, Preset};
use krypto::{Error, SecretString};

#[test]
fn hash_and_verify_ok() {
    let pw = SecretString::from_string("correct-horse-battery-11".to_string()).unwrap();
    let phc = password::hash(&pw, Preset::Interactive).unwrap();
    assert!(phc.starts_with("$argon2id$"), "PHC string: {phc}");
    let pw_again = SecretString::from_string("correct-horse-battery-11".to_string()).unwrap();
    password::verify(&pw_again, &phc).unwrap();
}

#[test]
fn wrong_password_gives_auth() {
    let pw = SecretString::from_string("right-password-123".to_string()).unwrap();
    let phc = password::hash(&pw, Preset::Interactive).unwrap();
    let wrong = SecretString::from_string("wrong-password-123".to_string()).unwrap();
    assert!(matches!(password::verify(&wrong, &phc), Err(Error::Auth)));
}

#[test]
fn invalid_phc_gives_format() {
    let pw = SecretString::from_string("password".to_string()).unwrap();
    assert!(matches!(
        password::verify(&pw, "not-a-valid-phc-string"),
        Err(Error::Format(_))
    ));
}

#[test]
fn foreign_hash_gives_format_not_auth() {
    // A scrypt PHC parses fine as PasswordHash, but Argon2::verify cannot
    // handle it → must give Format (corrupt/foreign hash), NOT Auth (which
    // would misdiagnose a database problem as "wrong password").
    let pw = SecretString::from_string("password".to_string()).unwrap();
    let scrypt_phc = "$scrypt$ln=16,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
    assert!(matches!(
        password::verify(&pw, scrypt_phc),
        Err(Error::Format(_))
    ));
}

/// The three presets are a public contract: the parameters behind each name
/// end up in the PHC string, so a consumer can see exactly what it got.
/// (0.5.0: `Moderate` → `High`, and `Balanced` is new.)
#[test]
fn presets_encode_their_parameters_in_the_phc_string() {
    let pw = SecretString::from_string("preset-check".to_string()).unwrap();
    for (preset, m_kib) in [
        (Preset::Interactive, 65_536u32),
        (Preset::Balanced, 131_072),
        (Preset::High, 262_144),
    ] {
        let phc = password::hash(&pw, preset).unwrap();
        assert!(
            phc.contains(&format!("m={m_kib}")),
            "{preset:?} should carry m={m_kib} in the PHC string: {phc}"
        );
        // Old hashes keep verifying after a profile revision because the
        // params live in the string itself.
        let again = SecretString::from_string("preset-check".to_string()).unwrap();
        password::verify(&again, &phc).unwrap();
    }
}
