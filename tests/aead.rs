//! Integration tests for the AEAD/blob layer (seal/open + master key + HKDF).

use krypto::{open, seal, Alg, Error, MasterKey, SecretBuf};

// Write a 32-byte master key to a temporary file and load it.
fn test_master(tag: &str) -> MasterKey {
    let path = std::env::temp_dir().join(format!(
        "krypto-test-master-{}-{tag}.key",
        std::process::id()
    ));
    std::fs::write(&path, [7u8; 32]).unwrap();
    let mk = MasterKey::from_secret_file(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    mk
}

fn roundtrip(alg: Alg) {
    let mk = test_master(&format!("rt-{alg:?}"));
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let key_id = [1u8; 16];
    let secret = SecretBuf::from_vec(b"secret-data-123".to_vec()).unwrap();

    let blob = seal(&dk, &key_id, &secret, alg).unwrap();
    // The blob must not contain plaintext.
    assert!(
        !blob.windows(6).any(|w| w == b"secret"),
        "plaintext leaked into the blob"
    );

    let out = open(&dk, &blob).unwrap();
    out.expose(|b| assert_eq!(b, b"secret-data-123"));
}

#[test]
fn roundtrip_aegis() {
    roundtrip(Alg::Aegis256);
}

#[test]
fn roundtrip_xchacha() {
    roundtrip(Alg::XChaCha20Poly1305);
}

#[test]
fn roundtrip_aes256gcm() {
    roundtrip(Alg::Aes256Gcm);
}

#[test]
fn aes256gcm_tampering_gives_auth_error() {
    // The same tampering guarantee for alg_id 3: header (key-id swap) AND ciphertext.
    let mk = test_master("aes");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"aes-secret".to_vec()).unwrap();

    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::Aes256Gcm).unwrap();
    blob[6] ^= 0xff; // key_id
    assert!(matches!(open(&dk, &blob), Err(Error::Auth)));

    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::Aes256Gcm).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01; // tag
    assert!(matches!(open(&dk, &blob), Err(Error::Auth)));
}

#[test]
fn alg_id_swap_between_algorithms_gives_auth_error() {
    // An AEGIS blob restamped to alg_id 3 must give Auth (the header is AAD),
    // never an AES decryption attempt that "succeeds".
    let mk = test_master("swap");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"swap-data".to_vec()).unwrap();
    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();
    blob[5] = 3; // alg_id: AEGIS-256 → AES-256-GCM
    assert!(matches!(open(&dk, &blob), Err(Error::Auth)));
}

#[test]
fn header_tampering_gives_auth_error() {
    // The key-id swap test: flip a byte in key_id (header) → Auth, not a mis-decrypt.
    let mk = test_master("ht");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"abc".to_vec()).unwrap();
    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();
    blob[6] ^= 0xff; // first byte of key_id (offset 4+1+1)
    match open(&dk, &blob) {
        Err(Error::Auth) => {}
        other => panic!("expected Auth on header tampering, got {other:?}"),
    }
}

#[test]
fn nonce_tampering_gives_auth_error() {
    // The nonce field is part of the header, which is AAD → tampering must give Auth.
    let mk = test_master("nonce");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"abcdef".to_vec()).unwrap();
    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();
    blob[22] ^= 0x01; // first nonce byte (offset 4+1+1+16)
    assert!(matches!(open(&dk, &blob), Err(Error::Auth)));
}

#[test]
fn empty_plaintext_roundtrip() {
    let mk = test_master("empty");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(Vec::new()).unwrap();
    let blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();
    let out = open(&dk, &blob).unwrap();
    out.expose(|b| assert!(b.is_empty()));
}

#[test]
fn ciphertext_tampering_gives_auth_error() {
    let mk = test_master("ct");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"abcdef".to_vec()).unwrap();
    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::XChaCha20Poly1305).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    assert!(matches!(open(&dk, &blob), Err(Error::Auth)));
}

#[test]
fn wrong_key_gives_auth_error() {
    let mk = test_master("wk");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"xyz".to_vec()).unwrap();
    let blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();
    // Different info → different derived key.
    let dk2 = mk.derive(b"krypto/other/v1", b"saltsalt").unwrap();
    assert!(matches!(open(&dk2, &blob), Err(Error::Auth)));
}

#[test]
fn truncated_blob_fails() {
    let mk = test_master("tr");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"data".to_vec()).unwrap();
    let blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();
    assert!(open(&dk, &blob[..10]).is_err());
}

#[test]
fn unknown_alg_id_gives_format_error() {
    let mk = test_master("alg");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"data".to_vec()).unwrap();
    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();
    blob[5] = 9; // alg_id → unknown
    assert!(matches!(open(&dk, &blob), Err(Error::Format(_))));
}

/// `blob_key_id` makes key rotation manageable without guessing.
///
/// The field has always been in the header, but without a way to read it a
/// consumer holding several key generations had to try them all — and read
/// `Error::Auth` as the outcome. `krypto-cli` defines exactly that error as
/// "tampering/wrong key, should be alarmed", so the operator got a security
/// alarm for a perfectly normal old-generation blob.
#[test]
fn key_id_is_readable_without_decrypting() {
    let mk = test_master("key-id");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let key_id = [0xABu8; 16];
    let secret = SecretBuf::from_vec(b"secret".to_vec()).unwrap();
    let blob = seal(&dk, &key_id, &secret, Alg::Aegis256).unwrap();

    assert_eq!(krypto::blob_key_id(&blob).unwrap(), key_id);
}

/// It must fail cleanly on garbage — no panics, and no invented values.
#[test]
fn key_id_rejects_invalid_blobs() {
    assert!(krypto::blob_key_id(b"").is_err(), "empty blob");
    assert!(krypto::blob_key_id(b"tiny").is_err(), "too short");
    let mut wrong_magic = vec![0u8; 64];
    wrong_magic[0..4].copy_from_slice(b"XXXX");
    assert!(krypto::blob_key_id(&wrong_magic).is_err(), "wrong magic");
}

/// Important limitation: the value is NOT authenticated until `open` succeeds.
/// It is for *choosing a key*, never for a trust decision — and a tampered
/// key_id must still yield `Auth` from `open`, not a mis-decrypt.
#[test]
fn tampered_key_id_reads_back_but_open_still_fails() {
    let mk = test_master("key-id");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let secret = SecretBuf::from_vec(b"secret".to_vec()).unwrap();
    let mut blob = seal(&dk, &[1u8; 16], &secret, Alg::Aegis256).unwrap();

    blob[6] ^= 0xff; // tamper with the first byte of key_id
                     // The read "succeeds" — it is plain header parsing, not a guarantee.
    assert_eq!(krypto::blob_key_id(&blob).unwrap()[0], 1u8 ^ 0xff);
    // But the header is AAD, so the open fails closed.
    assert!(matches!(open(&dk, &blob), Err(krypto::Error::Auth)));
}

// --- reseal (0.6.0 — the rotation action) ---

fn master_with(tag: &str, byte: u8) -> MasterKey {
    let path = std::env::temp_dir().join(format!(
        "krypto-test-master-{}-{tag}.key",
        std::process::id()
    ));
    std::fs::write(&path, [byte; 32]).unwrap();
    let mk = MasterKey::from_secret_file(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    mk
}

#[test]
fn reseal_moves_a_blob_to_a_new_key_generation() {
    let old_mk = master_with("rs-old", 7);
    let new_mk = master_with("rs-new", 8);
    let old_dk = old_mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let new_dk = new_mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let pt = SecretBuf::from_vec(b"rotate me".to_vec()).unwrap();
    let blob = seal(&old_dk, &[1u8; 16], &pt, Alg::Aegis256).unwrap();

    let rotated = krypto::reseal(&old_dk, &new_dk, &[2u8; 16], &blob).unwrap();

    // The new blob carries the new generation id and opens under the new key.
    assert_eq!(krypto::blob_key_id(&rotated).unwrap(), [2u8; 16]);
    let out = open(&new_dk, &rotated).unwrap();
    out.expose(|b| assert_eq!(b, b"rotate me"));
    // The old key no longer opens it — that is the point.
    assert!(matches!(open(&old_dk, &rotated), Err(Error::Auth)));
}

#[test]
fn reseal_preserves_the_algorithm() {
    let mk = test_master("rs-alg");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let pt = SecretBuf::from_vec(b"x".to_vec()).unwrap();
    let blob = seal(&dk, &[1u8; 16], &pt, Alg::XChaCha20Poly1305).unwrap();
    let rotated = krypto::reseal(&dk, &dk, &[2u8; 16], &blob).unwrap();
    // alg_id is byte 5 of the header; 2 = XChaCha20Poly1305.
    assert_eq!(
        rotated[5], 2,
        "a rotation changes the key, never the cipher"
    );
}

#[test]
fn reseal_with_the_wrong_old_key_is_auth_and_yields_nothing() {
    let old_mk = master_with("rs-w1", 7);
    let wrong_mk = master_with("rs-w2", 9);
    let old_dk = old_mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let wrong_dk = wrong_mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    let pt = SecretBuf::from_vec(b"x".to_vec()).unwrap();
    let blob = seal(&old_dk, &[1u8; 16], &pt, Alg::Aegis256).unwrap();
    assert!(matches!(
        krypto::reseal(&wrong_dk, &old_dk, &[2u8; 16], &blob),
        Err(Error::Auth)
    ));
}

#[test]
fn reseal_rejects_garbage_input() {
    let mk = test_master("rs-garbage");
    let dk = mk.derive(b"krypto/test/v1", b"saltsalt").unwrap();
    assert!(matches!(
        krypto::reseal(&dk, &dk, &[2u8; 16], b"not a blob"),
        Err(Error::Format(_))
    ));
}
