//! Signature layer: official vectors + roundtrips + failure modes.

use krypto::sign::{
    ecdsa_p256_keypair, ecdsa_p256_public, ecdsa_p256_sign, ecdsa_p256_verify, ed25519_keypair,
    ed25519_public, ed25519_sign, ed25519_verify,
};
use krypto::{hex, Error, SecretBuf};

fn seed_from_hex(s: &str) -> SecretBuf {
    SecretBuf::from_vec(hex::decode(s).unwrap()).unwrap()
}

// --------------------------------------------------------------------------- //
// Ed25519 — RFC 8032 §7.1
// --------------------------------------------------------------------------- //

/// RFC 8032 TEST 1: empty message.
#[test]
fn ed25519_rfc8032_test_1() {
    let seed = seed_from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = ed25519_public(&seed).unwrap();
    assert_eq!(
        hex::encode(&public),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let sig = ed25519_sign(&seed, b"").unwrap();
    assert_eq!(
        hex::encode(&sig),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    ed25519_verify(&public, b"", &sig).unwrap();
}

/// RFC 8032 TEST 2: one-byte message.
#[test]
fn ed25519_rfc8032_test_2() {
    let seed = seed_from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let public = ed25519_public(&seed).unwrap();
    assert_eq!(
        hex::encode(&public),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    let msg = hex::decode("72").unwrap();
    let sig = ed25519_sign(&seed, &msg).unwrap();
    assert_eq!(
        hex::encode(&sig),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    ed25519_verify(&public, &msg, &sig).unwrap();
}

#[test]
fn ed25519_roundtrip_and_failures() {
    let (seed, public) = ed25519_keypair().unwrap();
    let sig = ed25519_sign(&seed, b"a message").unwrap();
    ed25519_verify(&public, b"a message", &sig).unwrap();

    // Tampered message → Auth.
    assert!(matches!(
        ed25519_verify(&public, b"a messagE", &sig),
        Err(Error::Auth)
    ));
    // Tampered signature → Auth.
    let mut bad = sig;
    bad[63] ^= 0x01;
    assert!(matches!(
        ed25519_verify(&public, b"a message", &bad),
        Err(Error::Auth)
    ));
    // Wrong key → Auth.
    let (_seed2, public2) = ed25519_keypair().unwrap();
    assert!(matches!(
        ed25519_verify(&public2, b"a message", &sig),
        Err(Error::Auth)
    ));
    // Malformed inputs → Format, never a panic.
    assert!(matches!(
        ed25519_verify(&public[..31], b"m", &sig),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        ed25519_verify(&public, b"m", &sig[..63]),
        Err(Error::Format(_))
    ));
    let short_seed = SecretBuf::from_vec(vec![7u8; 16]).unwrap();
    assert!(matches!(
        ed25519_sign(&short_seed, b"m"),
        Err(Error::Format(_))
    ));
}

// --------------------------------------------------------------------------- //
// ECDSA P-256 — RFC 6979 A.2.5 (deterministic, SHA-256)
// --------------------------------------------------------------------------- //

/// RFC 6979 appendix A.2.5, message "sample": our PKCS#8 → DER signing path
/// must produce exactly the RFC's (r, s).
#[test]
fn ecdsa_p256_rfc6979_sample() {
    use p256::pkcs8::EncodePrivateKey;
    // Private scalar from the RFC.
    let x =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let sk = p256::ecdsa::SigningKey::from_slice(&x).unwrap();
    let pkcs8 = SecretBuf::from_vec(sk.to_pkcs8_der().unwrap().as_bytes().to_vec()).unwrap();

    let sig_der = ecdsa_p256_sign(&pkcs8, b"sample").unwrap();
    let fixed = p256::ecdsa::Signature::from_der(&sig_der)
        .unwrap()
        .to_bytes();
    assert_eq!(
        hex::encode(&fixed),
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
         f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    );

    let public = ecdsa_p256_public(&pkcs8).unwrap();
    assert_eq!(public.len(), 65);
    assert_eq!(public[0], 0x04, "uncompressed SEC1 point");
    ecdsa_p256_verify(&public, b"sample", &sig_der).unwrap();
}

#[test]
fn ecdsa_p256_roundtrip_and_failures() {
    let (private, public) = ecdsa_p256_keypair().unwrap();
    assert_eq!(public.len(), 65);
    assert_eq!(public[0], 0x04);

    let sig = ecdsa_p256_sign(&private, b"order-42").unwrap();
    ecdsa_p256_verify(&public, b"order-42", &sig).unwrap();

    // Tampered message → Auth.
    assert!(matches!(
        ecdsa_p256_verify(&public, b"order-43", &sig),
        Err(Error::Auth)
    ));
    // Wrong key → Auth.
    let (_p2, public2) = ecdsa_p256_keypair().unwrap();
    assert!(matches!(
        ecdsa_p256_verify(&public2, b"order-42", &sig),
        Err(Error::Auth)
    ));
    // Malformed inputs → Format.
    assert!(matches!(
        ecdsa_p256_verify(b"not-a-point", b"m", &sig),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        ecdsa_p256_verify(&public, b"m", b"not-der"),
        Err(Error::Format(_))
    ));
    let not_pkcs8 = SecretBuf::from_vec(vec![1u8; 32]).unwrap();
    assert!(matches!(
        ecdsa_p256_sign(&not_pkcs8, b"m"),
        Err(Error::Format(_))
    ));
}

/// The DER form must be what ring-based verifiers (nettls today) accept —
/// structurally: a DER SEQUENCE of two INTEGERs.
#[test]
fn ecdsa_p256_signature_is_der() {
    let (private, _public) = ecdsa_p256_keypair().unwrap();
    let sig = ecdsa_p256_sign(&private, b"wire-check").unwrap();
    assert_eq!(sig[0], 0x30, "DER SEQUENCE tag");
    assert_eq!(sig[1] as usize, sig.len() - 2, "DER length byte");
}
