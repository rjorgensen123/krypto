//! Argon2id password hashing via presets. Consumers never pick raw parameters.
//!
//! This is one-way hashing to *verify* passwords — not encryption.
//! (A peppered-HMAC layer on top of Argon2id is deliberately NOT built here:
//! if the portfolio ever wants that two-layer defence, the pepper belongs in
//! the consumer that owns login policy, not in this crate. Parked as a
//! possible future extension — see docs/Home.md.)

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::Error;
use crate::secret::SecretString;

/// Calibration preset. The floor follows SEC v10 (`m ≥ 64 MiB, t ≥ 2, p ≥ 1`).
///
/// The crate owns the numbers; the consumer picks a profile and stores its
/// **name**, never the parameters (they also live in the PHC string, so old
/// hashes keep verifying unchanged after a profile revision).
// 0.5.0: `Moderate` (256 MiB) was renamed to `High` — the name said "middle",
// the numbers were the strictest we have. `Balanced` is NEW and is the middle
// profile that was always missing.
#[derive(Clone, Copy, Debug)]
pub enum Preset {
    /// Interactive login: m = 64 MiB, t = 3, p = 2.
    Interactive,
    /// The middle ground: m = 128 MiB, t = 3, p = 3. For secrets worth more
    /// than a login round-trip but not worth 256 MiB per concurrent caller.
    /// (Numbers set 2026-08-26; free to tune — the PHC string carries them.)
    Balanced,
    /// High-value / offline-attackable targets: m = 256 MiB, t = 4, p = 4.
    /// (Named `Moderate` before 0.5.0 — same parameters, honest name.)
    High,
}

impl Preset {
    fn params(self) -> Params {
        let (m_kib, t, p) = match self {
            Preset::Interactive => (65_536, 3, 2), // 64 MiB
            Preset::Balanced => (131_072, 3, 3),   // 128 MiB
            Preset::High => (262_144, 4, 4),       // 256 MiB
        };
        Params::new(m_kib, t, p, None).expect("valid argon2 parameters")
    }
}

fn hasher(preset: Preset) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, preset.params())
}

/// Hash a password → PHC string (includes salt + params). Use when creating
/// or changing a password.
pub fn hash(password: &SecretString, preset: Preset) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    password.expose_str(|pw| {
        hasher(preset)
            .hash_password(pw.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| Error::Hardening(format!("argon2 hashing failed: {e}")))
    })
}

/// Verify a password against a PHC string (constant-time). `Ok(())` on match,
/// `Error::Auth` **only** on an actually wrong password, `Error::Format` on an
/// invalid/foreign/corrupt PHC string (e.g. a scrypt hash or unknown params) —
/// so a corrupt hash in the database is not misdiagnosed as "wrong password".
pub fn verify(password: &SecretString, phc: &str) -> Result<(), Error> {
    use argon2::password_hash::Error as PhError;

    let parsed =
        PasswordHash::new(phc).map_err(|e| Error::Format(format!("invalid PHC string: {e}")))?;
    password.expose_str(|pw| {
        // verify_password uses the params from the hash itself (parsed).
        match Argon2::default().verify_password(pw.as_bytes(), &parsed) {
            Ok(()) => Ok(()),
            Err(PhError::Password) => Err(Error::Auth),
            Err(e) => Err(Error::Format(format!("cannot verify hash: {e}"))),
        }
    })
}

// --------------------------------------------------------------------------- //
// Argon2id as KEY DERIVATION (KDF) — not as a stored hash
// --------------------------------------------------------------------------- //

/// Derive a 32-byte key from a password (SPEC SIKKERHETSMODELL §8.4).
///
/// # This is not the same as [`hash`]
///
/// Argon2 has two uses, and they must not be mixed:
///
/// | Use | What is stored | Where |
/// |---|---|---|
/// | **Verification** ([`hash`]/[`verify`]) | the PHC string | the user database — compared at login |
/// | **Key derivation** (this) | **nothing** — only salt and preset | unlocking data at rest |
///
/// For unlocking, **no** verification hash must be stored. If the password is
/// wrong, the AEAD authentication fails all by itself — fail-closed without
/// anyone writing a check. A stored hash next to the ciphertext would also
/// hand an attacker with the disk a **separate oracle** to test candidates
/// against, alongside the ciphertext he had to attack anyway.
///
/// # The salt
///
/// Must be at least 16 bytes and is stored in plaintext next to the
/// ciphertext. It is not a secret — its job is to make precomputed tables
/// useless, and it does that just as well in the open.
// 0.5.0: renamed from `utled_noekkel` (Norwegian → English; see CHANGELOG [0.5.0]).
pub fn derive_key(
    password: &SecretString,
    salt: &[u8],
    preset: Preset,
) -> Result<crate::secret::SecretBuf, Error> {
    if salt.len() < 16 {
        return Err(Error::Format(format!(
            "argon2 salt must be at least 16 bytes, got {}",
            salt.len()
        )));
    }
    let mut out = vec![0u8; 32];
    let res = password.expose_str(|pw| {
        hasher(preset)
            .hash_password_into(pw.as_bytes(), salt, &mut out)
            .map_err(|e| Error::Format(format!("argon2 derivation failed: {e}")))
    });
    match res {
        Ok(()) => crate::secret::SecretBuf::from_vec(out),
        Err(e) => {
            // Zeroize the half-finished key before releasing it.
            for b in out.iter_mut() {
                *b = 0;
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod kdf_tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from_string(s.to_string()).expect("valid")
    }

    const SALT: &[u8] = b"0123456789abcdef";

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_key(&pw("secret"), SALT, Preset::Interactive).unwrap();
        let b = derive_key(&pw("secret"), SALT, Preset::Interactive).unwrap();
        a.expose(|x| b.expose(|y| assert_eq!(x, y)));
    }

    #[test]
    fn different_password_gives_different_key() {
        let a = derive_key(&pw("secret"), SALT, Preset::Interactive).unwrap();
        let b = derive_key(&pw("secreT"), SALT, Preset::Interactive).unwrap();
        a.expose(|x| b.expose(|y| assert_ne!(x, y)));
    }

    #[test]
    fn different_salt_gives_different_key() {
        let a = derive_key(&pw("secret"), SALT, Preset::Interactive).unwrap();
        let b = derive_key(&pw("secret"), b"fedcba9876543210", Preset::Interactive).unwrap();
        a.expose(|x| b.expose(|y| assert_ne!(x, y)));
    }

    #[test]
    fn too_short_salt_is_rejected() {
        assert!(derive_key(&pw("x"), b"short", Preset::Interactive).is_err());
    }

    #[test]
    fn key_is_32_bytes() {
        let k = derive_key(&pw("x"), SALT, Preset::Interactive).unwrap();
        k.expose(|b| assert_eq!(b.len(), 32));
    }
}
