//! X25519 key agreement: RFC 7748 vectors + failure modes.

use krypto::exchange::{x25519_keypair, x25519_public, x25519_shared};
use krypto::{hex, Error, SecretBuf};

fn key_from_hex(s: &str) -> SecretBuf {
    SecretBuf::from_vec(hex::decode(s).unwrap()).unwrap()
}

/// RFC 7748 §6.1 — Alice and Bob arrive at the same shared secret, and every
/// value matches the RFC.
#[test]
fn x25519_rfc7748_vectors() {
    let alice = key_from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob = key_from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    let alice_pub = x25519_public(&alice).unwrap();
    let bob_pub = x25519_public(&bob).unwrap();
    assert_eq!(
        hex::encode(&alice_pub),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(&bob_pub),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );

    let shared_a = x25519_shared(&alice, &bob_pub).unwrap();
    let shared_b = x25519_shared(&bob, &alice_pub).unwrap();
    let expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    shared_a.expose(|a| assert_eq!(hex::encode(a), expected));
    shared_b.expose(|b| assert_eq!(hex::encode(b), expected));
}

#[test]
fn x25519_roundtrip_and_failures() {
    let (a_priv, a_pub) = x25519_keypair().unwrap();
    let (b_priv, b_pub) = x25519_keypair().unwrap();

    let s1 = x25519_shared(&a_priv, &b_pub).unwrap();
    let s2 = x25519_shared(&b_priv, &a_pub).unwrap();
    s1.expose(|x| s2.expose(|y| assert_eq!(x, y, "both sides must agree")));

    // A low-order peer point (all zeros) forces a non-contributory result —
    // must be rejected, never returned as an all-zero "shared secret".
    assert!(matches!(
        x25519_shared(&a_priv, &[0u8; 32]),
        Err(Error::Auth)
    ));
    // Wrong-length inputs → Format.
    assert!(matches!(
        x25519_shared(&a_priv, &[0u8; 31]),
        Err(Error::Format(_))
    ));
    let short = SecretBuf::from_vec(vec![1u8; 16]).unwrap();
    assert!(matches!(x25519_public(&short), Err(Error::Format(_))));
}
