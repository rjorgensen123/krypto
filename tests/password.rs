// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for argon2id password hashing.

use argon2::password_hash::PasswordHasher;
use argon2::{Algorithm, Argon2, AssociatedData, KeyId, Params, ParamsBuilder, Version};
use krypto::password::{self, Preset, MAX_PASSWORD_BYTES, MAX_PHC_BYTES};
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
    // A scrypt PHC parses fine as PasswordHash, but it is not Argon2id, so
    // krypto refuses it before argon2 runs → must give Format (corrupt/foreign
    // hash), NOT Auth (which would misdiagnose a database problem as "wrong
    // password").
    let pw = SecretString::from_string("password".to_string()).unwrap();
    let scrypt_phc = "$scrypt$ln=16,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
    assert!(matches!(
        password::verify(&pw, scrypt_phc),
        Err(Error::Format(_))
    ));
}

/// The three presets are a public contract: the parameters behind each name
/// end up in the PHC string, so a consumer can see exactly what it got.
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
        // params live in the string itself, as long as they stay within the
        // range `verify` accepts.
        let again = SecretString::from_string("preset-check".to_string()).unwrap();
        password::verify(&again, &phc).unwrap();
    }
}

// --------------------------------------------------------------------------- //
// What `verify` accepts (0.8.2): Argon2id, version 19, and parameters between
// the floor (m = 64 MiB, t = 2, p = 1) and the ceiling (High plus a margin:
// m = 320 MiB, t = 5, p = 5). Associated data is accepted; a `keyid` is not.
// Anything else is `Format`, even with the right password.
// --------------------------------------------------------------------------- //

const RANGE_PASSWORD: &str = "range-check-password";

/// A valid salt and hash field, for hand-written PHC strings that must be
/// refused before argon2 runs.
const SALT_AND_HASH: &str = "c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";

/// A PHC string made by argon2 itself for `RANGE_PASSWORD`, so the only thing
/// `verify` can refuse in it is the variant, version or parameters it carries.
fn argon2_phc(algorithm: Algorithm, version: Version, m_kib: u32, t: u32, p: u32) -> String {
    let params = Params::new(m_kib, t, p, None).unwrap();
    Argon2::new(algorithm, version, params)
        .hash_password(RANGE_PASSWORD.as_bytes())
        .unwrap()
        .to_string()
}

/// Asserts that `verify` refuses `phc` with `Format` given the right password,
/// and that the message carries neither the password nor the salt and hash.
fn assert_refused(phc: &str) {
    let pw = SecretString::from_string(RANGE_PASSWORD.to_string()).unwrap();
    match password::verify(&pw, phc) {
        Err(Error::Format(msg)) => {
            assert!(
                !msg.contains(RANGE_PASSWORD),
                "message carries the password: {msg}"
            );
            for field in phc.rsplit('$').take(2) {
                assert!(
                    !msg.contains(field),
                    "message carries the salt or hash: {msg}"
                );
            }
        }
        other => panic!("expected Format for {phc}, got {other:?}"),
    }
}

#[test]
fn argon2i_hash_gives_format() {
    let phc = argon2_phc(Algorithm::Argon2i, Version::V0x13, 65_536, 2, 1);
    assert_refused(&phc);
}

#[test]
fn argon2d_hash_gives_format() {
    let phc = argon2_phc(Algorithm::Argon2d, Version::V0x13, 65_536, 2, 1);
    assert_refused(&phc);
}

#[test]
fn version_16_gives_format() {
    let phc = argon2_phc(Algorithm::Argon2id, Version::V0x10, 65_536, 2, 1);
    assert!(phc.contains("$v=16$"), "PHC string: {phc}");
    assert_refused(&phc);
}

#[test]
fn missing_version_field_gives_format() {
    let phc = argon2_phc(Algorithm::Argon2id, Version::V0x13, 65_536, 2, 1);
    let without_version = phc.replacen("$v=19$", "$", 1);
    assert_ne!(without_version, phc, "PHC string: {phc}");
    assert_refused(&without_version);
}

#[test]
fn memory_above_the_ceiling_gives_format() {
    assert_refused(&format!("$argon2id$v=19$m=327681,t=2,p=1${SALT_AND_HASH}"));
}

#[test]
fn passes_above_the_ceiling_give_format() {
    assert_refused(&format!("$argon2id$v=19$m=65536,t=6,p=1${SALT_AND_HASH}"));
}

#[test]
fn parallelism_above_the_ceiling_gives_format() {
    assert_refused(&format!("$argon2id$v=19$m=65536,t=2,p=6${SALT_AND_HASH}"));
}

#[test]
fn memory_below_the_floor_gives_format() {
    let phc = argon2_phc(Algorithm::Argon2id, Version::V0x13, 65_535, 2, 1);
    assert_refused(&phc);
}

#[test]
fn passes_below_the_floor_give_format() {
    let phc = argon2_phc(Algorithm::Argon2id, Version::V0x13, 65_536, 1, 1);
    assert_refused(&phc);
}

/// argon2 cannot make a hash with p = 0, so the string is written by hand.
#[test]
fn parallelism_below_the_floor_gives_format() {
    assert_refused(&format!("$argon2id$v=19$m=65536,t=2,p=0${SALT_AND_HASH}"));
}

/// Asserts that `verify` accepts `phc` with the right password.
fn assert_verifies(phc: &str) {
    let pw = SecretString::from_string(RANGE_PASSWORD.to_string()).unwrap();
    if let Err(e) = password::verify(&pw, phc) {
        panic!("expected Ok for {phc}, got {e:?}");
    }
}

#[test]
fn parameters_at_the_floor_verify() {
    let phc = argon2_phc(Algorithm::Argon2id, Version::V0x13, 65_536, 2, 1);
    assert_verifies(&phc);
}

#[test]
fn parameters_at_the_ceiling_verify() {
    let phc = argon2_phc(Algorithm::Argon2id, Version::V0x13, 327_680, 5, 5);
    assert_verifies(&phc);
}

/// Associated data lives in the PHC string itself, so `verify` can use it.
#[test]
fn hash_with_associated_data_verifies() {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(65_536).t_cost(2).p_cost(1);
    builder.data(AssociatedData::new(b"example-data").unwrap());
    let phc = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        builder.build().unwrap(),
    )
    .hash_password(RANGE_PASSWORD.as_bytes())
    .unwrap()
    .to_string();
    assert!(phc.contains(",data="), "PHC string: {phc}");
    assert_verifies(&phc);
}

/// A `keyid` names a secret key (a pepper) that is not in the string, and
/// krypto has no way to be given it.
#[test]
fn hash_with_keyid_gives_format() {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(65_536).t_cost(2).p_cost(1);
    builder.keyid(KeyId::new(b"key-1").unwrap());
    let params = builder.build().unwrap();
    let phc = Argon2::new_with_secret(
        b"example-pepper",
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .unwrap()
    .hash_password(RANGE_PASSWORD.as_bytes())
    .unwrap()
    .to_string();
    assert!(phc.contains(",keyid="), "PHC string: {phc}");
    assert_refused(&phc);
}

/// The password is bounded (0.9.0): `MAX_PASSWORD_BYTES` is taken, one byte
/// more is `Format` in `hash`, `verify` and `derive_key`, refused before
/// Argon2 runs (`verify` would otherwise answer `Auth`).
#[test]
fn password_over_max_password_bytes_gives_format() {
    let at_cap = SecretString::from_string("p".repeat(MAX_PASSWORD_BYTES)).unwrap();
    let over = SecretString::from_string("p".repeat(MAX_PASSWORD_BYTES + 1)).unwrap();
    let phc = password::hash(&at_cap, Preset::Interactive).unwrap();
    password::verify(&at_cap, &phc).unwrap();
    password::derive_key(&at_cap, &[0u8; 16], Preset::Interactive).unwrap();

    assert!(matches!(
        password::hash(&over, Preset::Interactive),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        password::verify(&over, &phc),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        password::derive_key(&over, &[0u8; 16], Preset::Interactive),
        Err(Error::Format(_))
    ));
}

/// The PHC string is bounded (0.9.0): one of `MAX_PHC_BYTES` reaches the
/// parser, which refuses this one; one byte more is refused before it, with
/// the limit in the message. No string krypto accepts comes near the limit.
#[test]
fn phc_over_max_phc_bytes_gives_format() {
    let pw = SecretString::from_string("password".to_string()).unwrap();
    let at_cap = "x".repeat(MAX_PHC_BYTES);
    let over = "x".repeat(MAX_PHC_BYTES + 1);
    match password::verify(&pw, &at_cap) {
        Err(Error::Format(m)) => assert!(m.starts_with("invalid PHC string"), "{m}"),
        other => panic!("expected the parser's Format, got {other:?}"),
    }
    match password::verify(&pw, &over) {
        Err(Error::Format(m)) => assert!(m.ends_with(&format!("max {MAX_PHC_BYTES}")), "{m}"),
        other => panic!("expected Format for the length, got {other:?}"),
    }
}

/// The key `derive_key` gives for a fixed password, salt and preset, byte for
/// byte: a key derived once must be derived again unchanged, or what it sealed
/// can no longer be opened.
#[test]
fn derive_key_gives_the_known_key() {
    let pw = SecretString::from_string("example-password".to_string()).unwrap();
    let key = password::derive_key(&pw, b"example-salt-016", Preset::Interactive).unwrap();
    let hex = key.expose(|k| krypto::hex::encode(k).unwrap());
    assert_eq!(
        hex,
        "46f062b91e15996b13e9722e79d312094f78271935dc9432c8d6d6fb0e6adad0"
    );
}
