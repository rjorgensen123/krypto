// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signature layer: official vectors + roundtrips + failure modes.

use krypto::sign::{
    ecdsa_p256_keypair, ecdsa_p256_public, ecdsa_p256_sign, ecdsa_p256_verify, ed25519_keypair,
    ed25519_public, ed25519_sign, ed25519_verify, ed25519_verify_relaxed,
    MAX_ECDSA_P256_PKCS8_BYTES, MAX_ECDSA_P256_PUBLIC_BYTES, MAX_ECDSA_P256_SIG_BYTES,
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
        hex::encode(&public).unwrap(),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let sig = ed25519_sign(&seed, b"").unwrap();
    assert_eq!(
        hex::encode(&sig).unwrap(),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    ed25519_verify(&public, b"", &sig).unwrap();
    ed25519_verify_relaxed(&public, b"", &sig).unwrap();
}

/// RFC 8032 TEST 2: one-byte message.
#[test]
fn ed25519_rfc8032_test_2() {
    let seed = seed_from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let public = ed25519_public(&seed).unwrap();
    assert_eq!(
        hex::encode(&public).unwrap(),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    let msg = hex::decode("72").unwrap();
    let sig = ed25519_sign(&seed, &msg).unwrap();
    assert_eq!(
        hex::encode(&sig).unwrap(),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    ed25519_verify(&public, &msg, &sig).unwrap();
    ed25519_verify_relaxed(&public, &msg, &sig).unwrap();
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

/// Normal signatures verify with the relaxed function too, and it fails the
/// same way on a tampered message or a malformed input.
#[test]
fn ed25519_relaxed_roundtrip_and_failures() {
    for _ in 0..8 {
        let (seed, public) = ed25519_keypair().unwrap();
        let sig = ed25519_sign(&seed, b"a message").unwrap();
        ed25519_verify(&public, b"a message", &sig).unwrap();
        ed25519_verify_relaxed(&public, b"a message", &sig).unwrap();
        assert!(matches!(
            ed25519_verify_relaxed(&public, b"a messagE", &sig),
            Err(Error::Auth)
        ));
        assert!(matches!(
            ed25519_verify_relaxed(&public[..31], b"a message", &sig),
            Err(Error::Format(_))
        ));
        assert!(matches!(
            ed25519_verify_relaxed(&public, b"a message", &sig[..63]),
            Err(Error::Format(_))
        ));
    }
}

/// An S that is not below the group order L is refused with `Auth` by both
/// functions. RFC 8032 TEST 1 with L added to S still satisfies the signature
/// equation, so only the check on S refuses it; the unchanged signature
/// verifies.
#[test]
fn ed25519_s_not_below_the_group_order_is_refused() {
    let seed = seed_from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = ed25519_public(&seed).unwrap();
    let sig = ed25519_sign(&seed, b"").unwrap();
    ed25519_verify(&public, b"", &sig).unwrap();
    ed25519_verify_relaxed(&public, b"", &sig).unwrap();
    // L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032 §5.1),
    // little-endian like S.
    let order =
        hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
    let mut s_plus_l = sig;
    let mut carry = 0u16;
    for (byte, l) in s_plus_l[32..].iter_mut().zip(&order) {
        let sum = u16::from(*byte) + u16::from(*l) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 32 bytes");
    assert!(matches!(
        ed25519_verify(&public, b"", &s_plus_l),
        Err(Error::Auth)
    ));
    assert!(matches!(
        ed25519_verify_relaxed(&public, b"", &s_plus_l),
        Err(Error::Auth)
    ));
}

// --------------------------------------------------------------------------- //
// Ed25519 — weak keys and non-canonical keys (0.8.2)
// --------------------------------------------------------------------------- //

/// The canonical encodings of the 8 points of small order: the identity, the
/// point of order 2, the two of order 4 and the four of order 8.
const SMALL_ORDER_POINTS: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];

/// The identity point as public key, R = the identity and S = 0: the
/// signature equation holds for every message, without any private key.
#[test]
fn ed25519_identity_key_forgery_is_refused_strictly_and_accepted_relaxed() {
    let public = hex::decode(SMALL_ORDER_POINTS[0]).unwrap();
    let mut sig = [0u8; 64];
    sig[0] = 0x01; // R = identity, S = 0
    for message in [&b"msg1"[..], b"msg2", b"", b"any other message"] {
        assert!(matches!(
            ed25519_verify(&public, message, &sig),
            Err(Error::Auth)
        ));
        ed25519_verify_relaxed(&public, message, &sig).unwrap();
    }
}

/// Each small-order public key is refused by `ed25519_verify`. For each key a
/// forged signature is found that the relaxed function accepts: R = the base
/// point and S = 1, which holds for every message whose hash is a multiple of
/// the key's order. R is of prime order there, so the refusal is the key's.
#[test]
fn ed25519_every_small_order_key_is_refused() {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(
        &hex::decode("5866666666666666666666666666666666666666666666666666666666666666").unwrap(),
    );
    sig[32] = 0x01; // S = 1
    for point in SMALL_ORDER_POINTS {
        let public = hex::decode(point).unwrap();
        let forged = (0u32..256)
            .map(|i| format!("message {i}").into_bytes())
            .find(|m| ed25519_verify_relaxed(&public, m, &sig).is_ok())
            .unwrap_or_else(|| panic!("no forged message found for the key {point}"));
        assert!(
            matches!(ed25519_verify(&public, &forged, &sig), Err(Error::Auth)),
            "the small-order key {point} was not refused"
        );
    }
}

/// A public key that is not the canonical encoding of its point is `Format`
/// for `ed25519_verify`. `f0ff…7f` is y = p + 3 for the point with y = 3,
/// which is not of small order; the other two encode the identity.
#[test]
fn ed25519_non_canonical_key_is_format() {
    let mut identity_forgery = [0u8; 64];
    identity_forgery[0] = 0x01; // R = identity, S = 0
    let y3_canonical =
        hex::decode("0300000000000000000000000000000000000000000000000000000000000000").unwrap();
    let y3_non_canonical =
        hex::decode("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap();
    assert!(matches!(
        ed25519_verify(&y3_non_canonical, b"m", &identity_forgery),
        Err(Error::Format(_))
    ));
    // The point itself decodes: canonically encoded, and through the relaxed
    // function, the same signature only fails the equation.
    assert!(matches!(
        ed25519_verify(&y3_canonical, b"m", &identity_forgery),
        Err(Error::Auth)
    ));
    assert!(matches!(
        ed25519_verify_relaxed(&y3_non_canonical, b"m", &identity_forgery),
        Err(Error::Auth)
    ));

    for identity in [
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1
        "0100000000000000000000000000000000000000000000000000000000000080", // x = 0, sign bit set
    ] {
        let public = hex::decode(identity).unwrap();
        assert!(matches!(
            ed25519_verify(&public, b"m", &identity_forgery),
            Err(Error::Format(_))
        ));
        ed25519_verify_relaxed(&public, b"m", &identity_forgery).unwrap();
    }
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
        hex::encode(&fixed).unwrap(),
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

/// Whether `r` is the `Format` a length check gives, whose message ends with
/// the limit.
fn refused_for_length<T>(r: Result<T, Error>, max: usize) -> bool {
    matches!(r, Err(Error::Format(m)) if m.ends_with(&format!("max {max}")))
}

/// The P-256 keys and signature are bounded before they are parsed (0.9.0): a
/// 65-byte public key and a 72-byte signature verify, a 512-byte PKCS#8 key
/// reaches the parser, and one byte more than each is refused for its length.
#[test]
fn ecdsa_p256_inputs_over_their_limits_give_format() {
    let (private, public) = ecdsa_p256_keypair().unwrap();
    assert_eq!(public.len(), MAX_ECDSA_P256_PUBLIC_BYTES);
    // About one signature in four has the longest DER form.
    let (message, sig) = (0u32..256)
        .map(|i| format!("message {i}").into_bytes())
        .map(|m| {
            let sig = ecdsa_p256_sign(&private, &m).unwrap();
            (m, sig)
        })
        .find(|(_, sig)| sig.len() == MAX_ECDSA_P256_SIG_BYTES)
        .expect("no signature of the longest form in 256 messages");
    ecdsa_p256_verify(&public, &message, &sig).unwrap();

    let long_public = [&public[..], &[0]].concat();
    let long_sig = [&sig[..], &[0]].concat();
    assert!(refused_for_length(
        ecdsa_p256_verify(&long_public, &message, &sig),
        MAX_ECDSA_P256_PUBLIC_BYTES
    ));
    assert!(refused_for_length(
        ecdsa_p256_verify(&public, &message, &long_sig),
        MAX_ECDSA_P256_SIG_BYTES
    ));

    let at_cap = SecretBuf::from_vec(vec![0u8; MAX_ECDSA_P256_PKCS8_BYTES]).unwrap();
    let over = SecretBuf::from_vec(vec![0u8; MAX_ECDSA_P256_PKCS8_BYTES + 1]).unwrap();
    for r in [ecdsa_p256_public(&at_cap), ecdsa_p256_sign(&at_cap, b"m")] {
        assert!(matches!(r, Err(Error::Format(_))));
        assert!(!refused_for_length(r, MAX_ECDSA_P256_PKCS8_BYTES));
    }
    assert!(refused_for_length(
        ecdsa_p256_public(&over),
        MAX_ECDSA_P256_PKCS8_BYTES
    ));
    assert!(refused_for_length(
        ecdsa_p256_sign(&over, b"m"),
        MAX_ECDSA_P256_PKCS8_BYTES
    ));
}
