// SPDX-License-Identifier: MIT OR Apache-2.0
//! AEAD (`seal`/`open`) + the self-describing blob format (`FAFN`).
//!
//! Blob layout:
//! ```text
//! magic "FAFN" (4) | format_ver (1) | alg_id (1) | key_id (16) | nonce (32)
//!   | ciphertext | tag
//! ```
//! The header up to and including the nonce (54 bytes) is **associated data**,
//! so a blob never decrypts to anything but what was sealed (the key-id swap
//! test). *(0.9.0)* `seal_with_aad`/`open_with_aad`/`reseal_with_aad` append
//! caller-supplied associated data after that fixed-length header; an empty
//! caller AAD is exactly the AAD `seal`/`open` use, so the format is unchanged.
//! Data shorter than the 4-byte magic, or not starting with `FAFN`, is
//! not a krypto blob: `Error::Format`. Any other change — the blob cut short
//! of the 54-byte header, version, alg_id, key_id, nonce, ciphertext, tag —
//! is `Error::Auth` (0.7.3; the cut-short header since 0.9.0). A blob longer
//! than `MAX_DATA_BYTES` plus the header and the longest tag is
//! `Error::Format`, checked first (0.9.0).
//! The nonce field is a fixed 32 B; AES-256-GCM uses the first 12, XChaCha the
//! first 24, AEGIS-256 all 32, the rest zero.

use crate::error::Error;
use crate::kdf::DerivedKey;
use crate::secret::SecretBuf;
use crate::util::{check_data_len, MAX_DATA_BYTES};

const MAGIC: &[u8; 4] = b"FAFN";
const FORMAT_VER: u8 = 1;
const KEY_ID_LEN: usize = 16;
const NONCE_FIELD: usize = 32;
const HEADER_LEN: usize = 4 + 1 + 1 + KEY_ID_LEN + NONCE_FIELD; // 54
/// The longest tag of the three algorithms: AEGIS-256's 32 bytes.
const MAX_TAG_LEN: usize = 32;

/// The largest blob the functions that read one take (0.9.0): the blob of a
/// plaintext of [`MAX_DATA_BYTES`], with the 54-byte header and the longest
/// tag, so a blob `seal` makes always opens.
const MAX_BLOB_BYTES: usize = MAX_DATA_BYTES + HEADER_LEN + MAX_TAG_LEN;

/// Refuses a plaintext longer than [`MAX_DATA_BYTES`] with `Error::Format`
/// (0.9.0).
fn check_plaintext_len(len: usize) -> Result<(), Error> {
    check_data_len("plaintext", len)
}

/// Upper bound on the caller-supplied associated data of [`seal_with_aad`],
/// [`open_with_aad`] and [`reseal_with_aad`] (0.9.0).
///
/// It is the same size as the cap on `info` and salt,
/// [`crate::MAX_DERIVE_INPUT_BYTES`]. To bind a blob to something larger, pass
/// a hash of it as the AAD, for example one made with [`crate::sha256`].
pub const MAX_AAD_BYTES: usize = 1024;

/// Refuses an AAD longer than [`MAX_AAD_BYTES`] with `Error::Format`. `what`
/// is the parameter's name; the message carries only the lengths.
fn check_aad_len(what: &str, aad: &[u8]) -> Result<(), Error> {
    if aad.len() > MAX_AAD_BYTES {
        return Err(Error::Format(format!(
            "`{what}` is {} bytes — max {MAX_AAD_BYTES}",
            aad.len()
        )));
    }
    Ok(())
}

/// How much of the stack below `seal` and `open` is overwritten after the
/// cipher has run (0.8.2). The ciphers leave copies of the key in the stack
/// frames they used. Measured below the caller of `seal` and `open`, the
/// deepest of the three algorithms used about 9.9 KiB in an optimised build
/// and 55.9 KiB in a debug build. The size adds some to spare, and in a debug
/// build a wider margin for the extra frame `primitive_seal` and
/// `primitive_open` may take.
#[cfg(not(debug_assertions))]
const AEAD_SCRUB_BYTES: usize = 16 * 1024;
#[cfg(debug_assertions)]
const AEAD_SCRUB_BYTES: usize = 96 * 1024;

/// AEAD algorithm (the value is stored as `alg_id` in the blob header).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Alg {
    /// Default — `alg_id` 1.
    Aegis256,
    /// Variant (format-preserving exit) — `alg_id` 2.
    XChaCha20Poly1305,
    /// Interop bridge for peers that speak only AES-GCM (NIST SP 800-38D) — `alg_id` 3.
    ///
    /// (0.7.2) Its nonce is 12 random bytes, so one key should seal at most
    /// 2^32 blobs (NIST SP 800-38D, section 8.3). Beyond that, two blobs sharing
    /// a nonce becomes too likely, and a repeated nonce lets an attacker read
    /// the XOR of the two plaintexts and forge blobs. krypto keeps no count; for
    /// large volumes use [`Alg::Aegis256`], or derive a new key in time.
    Aes256Gcm,
}

impl Alg {
    fn id(self) -> u8 {
        match self {
            Alg::Aegis256 => 1,
            Alg::XChaCha20Poly1305 => 2,
            Alg::Aes256Gcm => 3,
        }
    }
    fn from_id(id: u8) -> Option<Alg> {
        match id {
            1 => Some(Alg::Aegis256),
            2 => Some(Alg::XChaCha20Poly1305),
            3 => Some(Alg::Aes256Gcm),
            _ => None,
        }
    }
    fn nonce_len(self) -> usize {
        match self {
            Alg::Aegis256 => 32,
            Alg::XChaCha20Poly1305 => 24,
            Alg::Aes256Gcm => 12,
        }
    }
}

/// Encrypt `plaintext` into a self-describing blob. `key_id` is written into the
/// header (identifies the master-key generation). The nonce is random per blob.
///
/// `plaintext` is at most [`MAX_DATA_BYTES`]; more is [`Error::Format`],
/// refused before a nonce is drawn or the key is used (0.9.0).
pub fn seal(
    key: &DerivedKey,
    key_id: &[u8; KEY_ID_LEN],
    plaintext: &SecretBuf,
    alg: Alg,
) -> Result<Vec<u8>, Error> {
    seal_with_aad(key, key_id, plaintext, alg, &[])
}

/// [`seal`] with caller-supplied associated data (0.9.0).
///
/// The AEAD's AAD is the 54-byte header followed by `aad` — the header has a
/// fixed length, so the concatenation is unambiguous and an empty `aad` is
/// byte-for-byte the AAD `seal` uses: **the blob format is unchanged** and
/// every blob sealed so far still opens. `aad` is *not* stored in the blob;
/// it must be supplied again at [`open_with_aad`], and a missing or different
/// `aad` fails with [`Error::Auth`] like any other tampering. Use it to bind a
/// blob to a context the plaintext should not carry — a record id, a channel,
/// a timestamp.
///
/// `aad` is at most [`MAX_AAD_BYTES`] bytes; a longer one is
/// [`Error::Format`], refused before a nonce is drawn or the key is used.
/// So is a `plaintext` over [`MAX_DATA_BYTES`] (0.9.0).
pub fn seal_with_aad(
    key: &DerivedKey,
    key_id: &[u8; KEY_ID_LEN],
    plaintext: &SecretBuf,
    alg: Alg,
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    check_aad_len("aad", aad)?;
    check_plaintext_len(plaintext.len())?;
    let mut nonce = [0u8; NONCE_FIELD];
    getrandom::fill(&mut nonce[..alg.nonce_len()])
        .map_err(|e| Error::Hardening(format!("getrandom failed: {e}")))?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VER);
    header.push(alg.id());
    header.extend_from_slice(key_id);
    header.extend_from_slice(&nonce);
    debug_assert_eq!(header.len(), HEADER_LEN);

    // The header has a fixed length (54), so header ++ aad is unambiguous and
    // empty aad is exactly the old AAD.
    let mut aad_full = Vec::with_capacity(HEADER_LEN + aad.len());
    aad_full.extend_from_slice(&header);
    aad_full.extend_from_slice(aad);

    let res = key.with_key(|k| {
        plaintext.expose(|pt| primitive_seal(alg, k, &nonce[..alg.nonce_len()], pt, &aad_full))
    });
    crate::secret::scrub_stack::<AEAD_SCRUB_BYTES>();
    let mut ct_tag = res??;

    let mut blob = header;
    blob.append(&mut ct_tag);
    Ok(blob)
}

/// Read a blob's header (0.7.3). Not starting with `FAFN` (or shorter than the
/// 4-byte magic) is not a krypto blob: `Format`. Starting with `FAFN` but cut
/// short of the 54-byte header is a changed blob: `Auth` (0.9.0) — the alarm
/// class is no longer the tamperer's choice. Past the magic, a version or an
/// algorithm this krypto does not know is `Auth`, like every other change to
/// a blob: a sealed blob that says otherwise has been altered.
///
/// A blob longer than `MAX_BLOB_BYTES` is `Format`, before the magic is looked
/// at (0.9.0).
fn read_header(blob: &[u8]) -> Result<(Alg, &[u8], &[u8]), Error> {
    if blob.len() > MAX_BLOB_BYTES {
        return Err(Error::Format(format!(
            "blob is {} bytes — max {MAX_BLOB_BYTES}",
            blob.len()
        )));
    }
    if blob.len() < 4 || &blob[..4] != MAGIC {
        return Err(Error::Format("wrong magic (not FAFN)".into()));
    }
    if blob.len() < HEADER_LEN {
        return Err(Error::Auth);
    }
    let (header, body) = blob.split_at(HEADER_LEN);
    if header[4] != FORMAT_VER {
        return Err(Error::Auth);
    }
    let alg = Alg::from_id(header[5]).ok_or(Error::Auth)?;
    Ok((alg, header, body))
}

/// Decrypt a blob. Verifies the header (as AAD) + the tag; `Error::Auth` on
/// tampering or a wrong key, `Error::Format` if `blob` is not a krypto blob at
/// all. Never panics on invalid input.
///
/// `blob` is at most [`MAX_DATA_BYTES`] plus 86 bytes (the 54-byte header and
/// the longest tag, 32 bytes), so every blob [`seal`] makes opens; a longer
/// one is `Error::Format`, before the magic is looked at (0.9.0).
pub fn open(key: &DerivedKey, blob: &[u8]) -> Result<SecretBuf, Error> {
    open_with_aad(key, blob, &[])
}

/// [`open`] with caller-supplied associated data (0.9.0). `aad` must be the
/// same value the blob was sealed with via [`seal_with_aad`]; it is not stored
/// in the blob, so a missing or different `aad` fails with [`Error::Auth`]
/// like any other tampering. An empty `aad` opens exactly the blobs `seal`
/// produces.
///
/// `aad` is at most [`MAX_AAD_BYTES`] bytes; a longer one is
/// [`Error::Format`], refused before the blob is read or the key is used. The
/// blob's limit is the one [`open`] has (0.9.0).
pub fn open_with_aad(key: &DerivedKey, blob: &[u8], aad: &[u8]) -> Result<SecretBuf, Error> {
    check_aad_len("aad", aad)?;
    let (alg, header, body) = read_header(blob)?;
    let nonce_start = 6 + KEY_ID_LEN;
    // `key_id` is covered by the AAD, so it cannot be tampered with silently —
    // but it was never READ out, and that made the rotation hook inert: a blob
    // sealed with the previous generation's key yielded `Error::Auth`, which
    // `krypto-cli` explicitly defines as "tampering/wrong key, should be
    // alarmed". The operator got a security alarm for a perfectly normal
    // old-generation blob. See `blob_key_id()` — the consumer can now ask
    // BEFORE attempting to open.
    let nonce = &header[nonce_start..nonce_start + NONCE_FIELD];

    // Same composition as `seal_with_aad`: the fixed-length header, then `aad`.
    let mut aad_full = Vec::with_capacity(HEADER_LEN + aad.len());
    aad_full.extend_from_slice(header);
    aad_full.extend_from_slice(aad);

    let res = key.with_key(|k| primitive_open(alg, k, &nonce[..alg.nonce_len()], body, &aad_full));
    crate::secret::scrub_stack::<AEAD_SCRUB_BYTES>();
    let pt = res??;
    SecretBuf::from_vec(pt)
}

/// Re-seal a blob under a new key generation — the rotation *action* (0.6.0).
///
/// Opens the blob with `old`, seals the plaintext with `new` under
/// `new_key_id`, **preserving the blob's algorithm** (a rotation changes the
/// key, never the cipher choice someone made at seal time). krypto is
/// stateless: both keys come from the caller, which owns when and why a
/// rotation happens and where the keys live.
///
/// Fail-closed: nothing is produced unless `open` authenticates the whole
/// blob (header as AAD + tag) with the old key — a wrong old key or a
/// tampered blob is [`Error::Auth`]. The plaintext exists only inside a
/// locked [`SecretBuf`] between the two operations.
///
/// The blob's limit is the one [`open`] has (0.9.0).
pub fn reseal(
    old: &DerivedKey,
    new: &DerivedKey,
    new_key_id: &[u8; KEY_ID_LEN],
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    reseal_with_aad(old, new, new_key_id, blob, &[], &[])
}

/// [`reseal`] with caller-supplied associated data (0.9.0): `old_aad` must
/// match the blob (as in [`open_with_aad`]), `new_aad` is bound into the new
/// blob (as in [`seal_with_aad`]). The algorithm is preserved, as in `reseal`.
///
/// `old_aad` and `new_aad` are each at most [`MAX_AAD_BYTES`] bytes; a longer
/// one is [`Error::Format`], refused before the blob is read or a key is used.
/// The blob's limit is the one [`open`] has (0.9.0).
pub fn reseal_with_aad(
    old: &DerivedKey,
    new: &DerivedKey,
    new_key_id: &[u8; KEY_ID_LEN],
    blob: &[u8],
    old_aad: &[u8],
    new_aad: &[u8],
) -> Result<Vec<u8>, Error> {
    check_aad_len("old_aad", old_aad)?;
    check_aad_len("new_aad", new_aad)?;
    let (alg, _, _) = read_header(blob)?;
    let pt = open_with_aad(old, blob, old_aad)?;
    seal_with_aad(new, new_key_id, &pt, alg, new_aad)
}

/// The `key_id` from a blob header, without attempting to decrypt.
///
/// Exists for **key rotation**: a consumer holding several generations can see
/// which key a blob was sealed with and pick the right one — instead of trying
/// them all and interpreting `Error::Auth` as tampering. The blob format has
/// always carried the field; only a way to read it was missing.
///
/// The value is **not authenticated at this point** — the header is AAD, so it
/// is verified only when [`open`] succeeds. It should therefore be used to
/// *choose a key*, never to make a trust decision. If it has been tampered
/// with, `open` fails regardless.
///
/// It reads the header as `open` does (0.7.3): `Format` if `blob` is not a
/// krypto blob, `Auth` for a version or an algorithm this krypto does not know.
/// A blob that starts with `FAFN` but is cut short of the 54-byte header is
/// `Auth` here too (0.9.0). The blob's limit is the one [`open`] has (0.9.0).
pub fn blob_key_id(blob: &[u8]) -> Result<[u8; KEY_ID_LEN], Error> {
    let (_, header, _) = read_header(blob)?;
    let mut out = [0u8; KEY_ID_LEN];
    out.copy_from_slice(&header[6..6 + KEY_ID_LEN]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Primitives — caller-supplied nonce + AAD (the basis for interop adapters)
// ---------------------------------------------------------------------------

/// Kept out of line (0.8.2), so the cipher and its copies of the key live in
/// frames below the caller's, where the caller's `scrub_stack` reaches them.
#[inline(never)]
fn primitive_seal(
    alg: Alg,
    key: &[u8; 32],
    nonce: &[u8],
    pt: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    match alg {
        Alg::XChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::{XChaCha20Poly1305, XNonce};
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::Hardening("invalid key length".into()))?;
            // 0.7.2: the nonce conversion is fallible (the current `aead` dropped
            // the panicking one), so a wrong length is `Format`, as for AEGIS-256.
            let n = <&XNonce>::try_from(nonce)
                .map_err(|_| Error::Format("XChaCha20-Poly1305 requires a 24 B nonce".into()))?;
            c.encrypt(n, Payload { msg: pt, aad })
                .map_err(|_| Error::Hardening("AEAD encryption failed".into()))
        }
        Alg::Aegis256 => {
            use aegis::aegis256::Aegis256;
            let nonce32: &[u8; 32] = nonce
                .try_into()
                .map_err(|_| Error::Format("AEGIS-256 requires a 32 B nonce".into()))?;
            // NOTE (0.5.0): the argument order is `new(key, nonce)`. Up to and
            // including 0.4.4 these were SWAPPED — both are &[u8; 32] here, so
            // the compiler could not tell, and roundtrip tests passed because
            // seal and open made the same mistake. Found by the official
            // test vectors below; see CHANGELOG [0.5.0].
            let cipher = Aegis256::<32>::new(key, nonce32);
            let (mut ct, tag) = cipher.encrypt(pt, aad);
            ct.extend_from_slice(&tag);
            Ok(ct)
        }
        Alg::Aes256Gcm => {
            use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
            use aes_gcm::Aes256Gcm;
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Hardening("invalid key length".into()))?;
            let n = <&Nonce<Aes256Gcm>>::try_from(nonce)
                .map_err(|_| Error::Format("AES-256-GCM requires a 12 B nonce".into()))?;
            c.encrypt(n, Payload { msg: pt, aad })
                .map_err(|_| Error::Hardening("AEAD encryption failed".into()))
        }
    }
}

/// Kept out of line (0.8.2), for the same reason as `primitive_seal`.
#[inline(never)]
fn primitive_open(
    alg: Alg,
    key: &[u8; 32],
    nonce: &[u8],
    body: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    match alg {
        Alg::XChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::{XChaCha20Poly1305, XNonce};
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::Hardening("invalid key length".into()))?;
            // 0.7.2: fallible nonce conversion, see `primitive_seal`.
            let n = <&XNonce>::try_from(nonce)
                .map_err(|_| Error::Format("XChaCha20-Poly1305 requires a 24 B nonce".into()))?;
            c.decrypt(n, Payload { msg: body, aad })
                .map_err(|_| Error::Auth)
        }
        Alg::Aegis256 => {
            use aegis::aegis256::Aegis256;
            const TAG: usize = 32;
            // A body cut short is a changed blob: `Auth`, as for the other
            // two algorithms (0.7.3).
            if body.len() < TAG {
                return Err(Error::Auth);
            }
            let (ct, tag) = body.split_at(body.len() - TAG);
            let tag_arr: &[u8; TAG] = tag
                .try_into()
                .map_err(|_| Error::Format("invalid tag length".into()))?;
            let nonce32: &[u8; 32] = nonce
                .try_into()
                .map_err(|_| Error::Format("AEGIS-256 requires a 32 B nonce".into()))?;
            // 0.5.0: `new(key, nonce)` — swapped before 0.5.0, see `primitive_seal`.
            let cipher = Aegis256::<TAG>::new(key, nonce32);
            cipher.decrypt(ct, tag_arr, aad).map_err(|_| Error::Auth)
        }
        Alg::Aes256Gcm => {
            use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
            use aes_gcm::Aes256Gcm;
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Hardening("invalid key length".into()))?;
            let n = <&Nonce<Aes256Gcm>>::try_from(nonce)
                .map_err(|_| Error::Format("AES-256-GCM requires a 12 B nonce".into()))?;
            c.decrypt(n, Payload { msg: body, aad })
                .map_err(|_| Error::Auth)
        }
    }
}

#[cfg(test)]
mod limits {
    use super::*;

    /// The check `seal` runs on the plaintext (0.9.0). A `SecretBuf` over the
    /// limit would need 64 MiB of locked memory, so the check is shown on the
    /// length it is given.
    #[test]
    fn plaintext_over_max_data_bytes_gives_format() {
        assert!(check_plaintext_len(MAX_DATA_BYTES).is_ok());
        assert!(matches!(
            check_plaintext_len(MAX_DATA_BYTES + 1),
            Err(Error::Format(_))
        ));
    }
}

// ---------------------------------------------------------------------------
// Known-answer tests against OFFICIAL vectors — "verified only against itself"
// must not be true of this crate. They target the primitive layer, where the
// caller-supplied nonce makes deterministic verification possible.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod official_vectors {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn check(alg: Alg, key: &str, nonce: &str, ad: &str, msg: &str, ct_tag: &str) {
        let key: [u8; 32] = unhex(key).try_into().unwrap();
        let nonce = unhex(nonce);
        let ad = unhex(ad);
        let msg = unhex(msg);
        let expected = unhex(ct_tag);

        let sealed = primitive_seal(alg, &key, &nonce, &msg, &ad).unwrap();
        assert_eq!(sealed, expected, "{alg:?}: ciphertext||tag mismatch");

        let opened = primitive_open(alg, &key, &nonce, &expected, &ad).unwrap();
        assert_eq!(opened, msg, "{alg:?}: decrypt mismatch");

        // And the tag must actually be load-bearing.
        let mut bad = expected.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(primitive_open(alg, &key, &nonce, &bad, &ad).is_err());
    }

    /// RFC 10032, Appendix A.3.4: AEGIS-256 Test Vector 3 (256-bit tag — the tag
    /// length this crate uses).
    #[test]
    fn aegis256_rfc10032_vector_3() {
        check(
            Alg::Aegis256,
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            // ct || tag256
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711\
             b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a",
        );
    }

    /// RFC 10032, Appendix A.3.3: AEGIS-256 Test Vector 2 (empty msg and ad — the
    /// tag alone carries the authentication).
    #[test]
    fn aegis256_rfc10032_vector_2_empty() {
        check(
            Alg::Aegis256,
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "",
            "",
            "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a",
        );
    }

    /// draft-arciszewski-xchacha-03, appendix A.1 ("Ladies and Gentlemen…").
    #[test]
    fn xchacha20poly1305_draft_vector_a1() {
        let msg_hex: String = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it."
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        check(
            Alg::XChaCha20Poly1305,
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "50515253c0c1c2c3c4c5c6c7",
            &msg_hex,
            "bd6d179d3e83d43b9576579493c0e9395\
             72a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e\
             c0875924c1c7987947deafd8780acf49",
        );
    }

    /// NIST CAVS `gcmEncryptExtIV256.rsp` (via the aes-gcm crate's bundled
    /// vectors): 256-bit key, 96-bit IV, 16-byte plaintext, empty AAD.
    #[test]
    fn aes256gcm_nist_cavs_vector() {
        check(
            Alg::Aes256Gcm,
            "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
            "0d18e06c7c725ac9e362e1ce",
            "",
            "2db5168e932556f8089a0622981d017d",
            "fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489",
        );
    }
}
