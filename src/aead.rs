//! AEAD (`seal`/`open`) + the self-describing blob format (`FAFN`).
//!
//! Blob layout:
//! ```text
//! magic "FAFN" (4) | format_ver (1) | alg_id (1) | key_id (16) | nonce (32)
//!   | ciphertext | tag
//! ```
//! The header up to and including the nonce (54 bytes) is **associated data** —
//! tampering with magic/version/alg_id/key_id/nonce yields `Error::Auth`, never
//! a mis-decrypt (the key-id swap test). The nonce field is a fixed 32 B;
//! AES-256-GCM uses the first 12, XChaCha the first 24, AEGIS-256 all 32, the
//! rest zero.

use crate::error::Error;
use crate::kdf::DerivedKey;
use crate::secret::SecretBuf;

const MAGIC: &[u8; 4] = b"FAFN";
const FORMAT_VER: u8 = 1;
const KEY_ID_LEN: usize = 16;
const NONCE_FIELD: usize = 32;
const HEADER_LEN: usize = 4 + 1 + 1 + KEY_ID_LEN + NONCE_FIELD; // 54

/// AEAD algorithm (the value is stored as `alg_id` in the blob header).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Alg {
    /// Default — `alg_id` 1.
    Aegis256,
    /// Variant (format-preserving exit) — `alg_id` 2.
    XChaCha20Poly1305,
    /// Interop bridge for peers that speak only AES-GCM (NIST SP 800-38D) — `alg_id` 3.
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
    fn from_id(id: u8) -> Result<Alg, Error> {
        match id {
            1 => Ok(Alg::Aegis256),
            2 => Ok(Alg::XChaCha20Poly1305),
            3 => Ok(Alg::Aes256Gcm),
            other => Err(Error::Format(format!("unknown alg_id {other}"))),
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
pub fn seal(
    key: &DerivedKey,
    key_id: &[u8; KEY_ID_LEN],
    plaintext: &SecretBuf,
    alg: Alg,
) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_FIELD];
    getrandom::getrandom(&mut nonce[..alg.nonce_len()])
        .map_err(|e| Error::Hardening(format!("getrandom failed: {e}")))?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VER);
    header.push(alg.id());
    header.extend_from_slice(key_id);
    header.extend_from_slice(&nonce);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let mut ct_tag = key.with_key(|k| {
        plaintext.expose(|pt| primitive_seal(alg, k, &nonce[..alg.nonce_len()], pt, &header))
    })??;

    let mut blob = header;
    blob.append(&mut ct_tag);
    Ok(blob)
}

/// Decrypt a blob. Verifies the header (as AAD) + the tag; `Error::Auth` on
/// tampering or a wrong key. Never panics on invalid input.
pub fn open(key: &DerivedKey, blob: &[u8]) -> Result<SecretBuf, Error> {
    if blob.len() < HEADER_LEN {
        return Err(Error::Format("blob shorter than header".into()));
    }
    let (header, body) = blob.split_at(HEADER_LEN);
    if &header[0..4] != MAGIC {
        return Err(Error::Format("wrong magic (not FAFN)".into()));
    }
    if header[4] != FORMAT_VER {
        return Err(Error::Format(format!(
            "unsupported format_ver {}",
            header[4]
        )));
    }
    let alg = Alg::from_id(header[5])?;
    let nonce_start = 6 + KEY_ID_LEN;
    // `key_id` is covered by the AAD, so it cannot be tampered with silently —
    // but it was never READ out, and that made the rotation hook inert: a blob
    // sealed with the previous generation's key yielded `Error::Auth`, which
    // `krypto-cli` explicitly defines as "tampering/wrong key, should be
    // alarmed". The operator got a security alarm for a perfectly normal
    // old-generation blob. See `blob_key_id()` — the consumer can now ask
    // BEFORE attempting to open.
    let nonce = &header[nonce_start..nonce_start + NONCE_FIELD];

    let pt =
        key.with_key(|k| primitive_open(alg, k, &nonce[..alg.nonce_len()], body, header))??;
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
pub fn reseal(
    old: &DerivedKey,
    new: &DerivedKey,
    new_key_id: &[u8; KEY_ID_LEN],
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    let alg = blob_alg(blob)?;
    let pt = open(old, blob)?;
    seal(new, new_key_id, &pt, alg)
}

/// The algorithm from a blob header (magic/version checked). Internal — the
/// public self-description contract is that `open` reads it; `reseal` needs
/// it to preserve the choice.
fn blob_alg(blob: &[u8]) -> Result<Alg, Error> {
    if blob.len() < HEADER_LEN {
        return Err(Error::Format("blob shorter than header".into()));
    }
    if &blob[0..4] != MAGIC {
        return Err(Error::Format("wrong magic (not FAFN)".into()));
    }
    if blob[4] != FORMAT_VER {
        return Err(Error::Format(format!("unsupported format_ver {}", blob[4])));
    }
    Alg::from_id(blob[5])
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
pub fn blob_key_id(blob: &[u8]) -> Result<[u8; KEY_ID_LEN], Error> {
    if blob.len() < HEADER_LEN {
        return Err(Error::Format("blob shorter than header".into()));
    }
    if &blob[0..4] != MAGIC {
        return Err(Error::Format("wrong magic (not FAFN)".into()));
    }
    if blob[4] != FORMAT_VER {
        return Err(Error::Format(format!("unsupported format_ver {}", blob[4])));
    }
    let mut out = [0u8; KEY_ID_LEN];
    out.copy_from_slice(&blob[6..6 + KEY_ID_LEN]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Primitives — caller-supplied nonce + AAD (the basis for interop adapters)
// ---------------------------------------------------------------------------

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
            c.encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
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
            // draft vectors below; see CHANGELOG [0.5.0].
            let cipher = Aegis256::<32>::new(key, nonce32);
            let (mut ct, tag) = cipher.encrypt(pt, aad);
            ct.extend_from_slice(&tag);
            Ok(ct)
        }
        Alg::Aes256Gcm => {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::{Aes256Gcm, Nonce};
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Hardening("invalid key length".into()))?;
            c.encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
                .map_err(|_| Error::Hardening("AEAD encryption failed".into()))
        }
    }
}

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
            c.decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
                .map_err(|_| Error::Auth)
        }
        Alg::Aegis256 => {
            use aegis::aegis256::Aegis256;
            const TAG: usize = 32;
            if body.len() < TAG {
                return Err(Error::Format("AEGIS-256 body shorter than tag".into()));
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
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::{Aes256Gcm, Nonce};
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Hardening("invalid key length".into()))?;
            c.decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad })
                .map_err(|_| Error::Auth)
        }
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
        assert!(s.len() % 2 == 0, "odd hex length");
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

    /// draft-irtf-cfrg-aegis-aead, AEGIS-256 Test Vector 3 (256-bit tag —
    /// the tag length this crate uses).
    #[test]
    fn aegis256_draft_vector_3() {
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

    /// draft-irtf-cfrg-aegis-aead, AEGIS-256 Test Vector 2 (empty msg and ad —
    /// the tag alone carries the authentication).
    #[test]
    fn aegis256_draft_vector_2_empty() {
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
