// SPDX-License-Identifier: MIT OR Apache-2.0
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
        hex::encode(&alice_pub).unwrap(),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(&bob_pub).unwrap(),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );

    let shared_a = x25519_shared(&alice, &bob_pub).unwrap();
    let shared_b = x25519_shared(&bob, &alice_pub).unwrap();
    let expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    shared_a.expose(|a| assert_eq!(hex::encode(a).unwrap(), expected));
    shared_b.expose(|b| assert_eq!(hex::encode(b).unwrap(), expected));
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

/// The u-coordinates of the low-order points below 2^255, as 32 bytes
/// little-endian, with p = 2^255 - 19.
const LOW_ORDER_POINTS: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000", // 0
    "0100000000000000000000000000000000000000000000000000000000000000", // 1
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1
];

/// Every low-order peer point is refused with `Auth`, for two private keys.
/// The seven encodings above are on D. J. Bernstein's Curve25519 page
/// (<https://cr.yp.to/ecdh.html>), in libsodium's `has_small_order` table and
/// in the Wycheproof X25519 vectors. The same seven with the top bit set are
/// the same points, since RFC 7748 §5 masks that bit; libsodium compares with
/// the bit masked, and the Wycheproof vectors hold them. The refusal is the
/// all-zero check of RFC 7748 §6.1.
#[test]
fn x25519_every_low_order_peer_point_is_refused() {
    let alice = key_from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let (fresh, _) = x25519_keypair().unwrap();

    let mut encodings = Vec::new();
    for point in LOW_ORDER_POINTS {
        let canonical: [u8; 32] = hex::decode(point).unwrap().try_into().unwrap();
        assert_eq!(canonical[31] & 0x80, 0, "{point} has the top bit set");
        let mut top_bit_set = canonical;
        top_bit_set[31] |= 0x80;
        encodings.push(canonical);
        encodings.push(top_bit_set);
    }
    assert_eq!(encodings.len(), 14);

    for key in [&alice, &fresh] {
        for encoding in &encodings {
            assert!(
                matches!(x25519_shared(key, encoding), Err(Error::Auth)),
                "the low-order point {} was not refused",
                hex::encode(encoding).unwrap()
            );
        }
    }
}

/// The five further values on D. J. Bernstein's list (p + a, p + b, 2p - 1, 2p
/// and 2p + 1, with a and b the two points of order 8) are low-order only when
/// all 256 bits are read as one integer. RFC 7748 §5 requires the top bit to
/// be masked, so they are ordinary points and give a shared secret; refusing
/// them would not follow the RFC.
#[test]
fn x25519_top_bit_is_masked_so_256_bit_low_order_values_are_accepted() {
    let alice = key_from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    for value in [
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", // p + a
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7", // p + b
        "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // 2p - 1
        "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // 2p
        "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // 2p + 1
    ] {
        let peer = hex::decode(value).unwrap();
        assert!(
            x25519_shared(&alice, &peer).is_ok(),
            "the ordinary point {value} was refused"
        );
    }

    // 2p with the top bit masked is 2^255 - 38: the same point.
    let two_p =
        hex::decode("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
    let masked =
        hex::decode("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap();
    let s1 = x25519_shared(&alice, &two_p).unwrap();
    let s2 = x25519_shared(&alice, &masked).unwrap();
    s1.expose(|x| s2.expose(|y| assert_eq!(x, y, "2p and 2^255 - 38 must give the same secret")));
}
