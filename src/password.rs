// SPDX-License-Identifier: MIT OR Apache-2.0
//! Argon2id password hashing via presets. Consumers never pick raw parameters.
//!
//! This is one-way hashing to *verify* passwords — not encryption.
//! (A peppered-HMAC layer on top of Argon2id is deliberately NOT built here:
//! if an application wants that two-layer defence, the pepper belongs in
//! the consumer that owns login policy, not in this crate.)

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::Error;
use crate::secret::SecretString;

/// Calibration preset. The floor follows SEC v10 (`m ≥ 64 MiB, t ≥ 2, p ≥ 1`).
///
/// The crate owns the numbers; the consumer picks a profile and stores its
/// **name**, never the parameters (they also live in the PHC string, so old
/// hashes keep verifying unchanged after a profile revision).
#[derive(Clone, Copy, Debug)]
pub enum Preset {
    /// Interactive login: m = 64 MiB, t = 3, p = 2.
    Interactive,
    /// The middle ground: m = 128 MiB, t = 3, p = 3. For secrets worth more
    /// than a login round-trip but not worth 256 MiB per concurrent caller.
    Balanced,
    /// High-value / offline-attackable targets: m = 256 MiB, t = 4, p = 4.
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

/// How much of the stack below the caller is overwritten after an argon2
/// call (0.7.2). argon2, and the hash it uses inside, leave copies of the
/// values they derive from the password, the derived key included, in the
/// stack frames they used, down to the deepest of them. The size covers all
/// the stack argon2 itself uses, with a little to spare: about 10-13 KiB in an
/// optimised build and 87-93 KiB in a debug build, whatever the preset.
#[cfg(not(debug_assertions))]
const SCRUB_BYTES: usize = 16 * 1024;
#[cfg(debug_assertions)]
const SCRUB_BYTES: usize = 128 * 1024;

/// Hash a password → PHC string (includes salt + params). Use when creating
/// or changing a password.
pub fn hash(password: &SecretString, preset: Preset) -> Result<String, Error> {
    let res = password.expose_str(|pw| {
        // `hash_password` draws a fresh 16-byte salt from the OS CSPRNG.
        hasher(preset)
            .hash_password(pw.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| Error::Hardening(format!("argon2 hashing failed: {e}")))
    });
    crate::secret::scrub_stack::<SCRUB_BYTES>();
    res
}

/// Verify a password against a PHC string (constant-time). `Ok(())` on match,
/// `Error::Auth` **only** on an actually wrong password, `Error::Format` on an
/// invalid/foreign/corrupt PHC string (e.g. a scrypt hash or unknown params) —
/// so a corrupt hash in the database is not misdiagnosed as "wrong password".
pub fn verify(password: &SecretString, phc: &str) -> Result<(), Error> {
    use argon2::password_hash::Error as PhError;

    let parsed =
        PasswordHash::new(phc).map_err(|e| Error::Format(format!("invalid PHC string: {e}")))?;
    let res = password.expose_str(|pw| {
        // verify_password uses the params from the hash itself (parsed).
        match Argon2::default().verify_password(pw.as_bytes(), &parsed) {
            Ok(()) => Ok(()),
            Err(PhError::PasswordInvalid) => Err(Error::Auth),
            Err(e) => Err(Error::Format(format!("cannot verify hash: {e}"))),
        }
    });
    crate::secret::scrub_stack::<SCRUB_BYTES>();
    res
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
    // The key is written straight into locked memory (0.7.2).
    let res = crate::secret::SecretBuf::fill_with(32, |out| {
        password.expose_str(|pw| {
            hasher(preset)
                .hash_password_into(pw.as_bytes(), salt, out)
                .map_err(|e| Error::Format(format!("argon2 derivation failed: {e}")))
        })
    });
    crate::secret::scrub_stack::<SCRUB_BYTES>();
    res
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
