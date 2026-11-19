// SPDX-License-Identifier: MIT OR Apache-2.0
//! Argon2id password hashing via presets. Consumers never pick raw parameters.
//!
//! [`verify`] accepts only hashes krypto makes or can make (0.8.2): Argon2id,
//! version 19, with parameters between the floor and a ceiling a little above
//! [`Preset::High`]. Other variants, versions and parameters are
//! `Error::Format`; [`verify`] has the details.
//!
//! This is one-way hashing to *verify* passwords — not encryption.
//! (A peppered-HMAC layer on top of Argon2id is deliberately NOT built here:
//! if an application wants that two-layer defence, the pepper belongs in
//! the consumer that owns login policy, not in this crate.)

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroize;

use crate::error::Error;
use crate::kdf::MAX_DERIVE_INPUT_BYTES;
use crate::secret::SecretString;

/// The longest password [`hash`], [`verify`] and [`derive_key`] take, in bytes
/// (0.9.0). A longer one is `Error::Format`, refused before Argon2 runs.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// The longest PHC string [`verify`] takes, in bytes (0.9.0). A longer one is
/// `Error::Format`, refused before it is parsed.
pub const MAX_PHC_BYTES: usize = 512;

/// Refuses a password longer than [`MAX_PASSWORD_BYTES`] with `Error::Format`
/// (0.9.0). The message carries only the lengths.
fn check_password_len(password: &SecretString) -> Result<(), Error> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Error::Format(format!(
            "password is {} bytes — max {MAX_PASSWORD_BYTES}",
            password.len()
        )));
    }
    Ok(())
}

/// Calibration preset. The floor follows SEC v10 (`m ≥ 64 MiB, t ≥ 2, p ≥ 1`),
/// and [`verify`] refuses hashes below it (0.8.2).
///
/// The crate owns the numbers; the consumer picks a profile and stores its
/// **name**, never the parameters (they also live in the PHC string, so old
/// hashes keep verifying unchanged after a profile revision, as long as they
/// stay within the range [`verify`] accepts).
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
///
/// `password` is at most [`MAX_PASSWORD_BYTES`]; a longer one is
/// `Error::Format`, refused before Argon2 runs (0.9.0).
pub fn hash(password: &SecretString, preset: Preset) -> Result<String, Error> {
    check_password_len(password)?;
    // argon2 draws the salt itself, so it is refused here, like krypto's own
    // requests for random bytes, once the random source is closed (0.9.0).
    crate::util::check_random_source_open()?;
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

/// The lowest memory cost, in KiB, a stored hash may carry (0.8.2): the SEC v10
/// floor of 64 MiB.
const MIN_M_KIB: u32 = 65_536;
/// The lowest number of passes a stored hash may carry (0.8.2): the SEC v10 floor.
const MIN_T: u32 = 2;
/// The lowest parallelism a stored hash may carry (0.8.2): the SEC v10 floor.
const MIN_P: u32 = 1;

/// Refuse a parsed PHC string that krypto does not make or could not make
/// (0.8.2), before argon2 does any work: anything but Argon2id, a version
/// other than 19 or no `v=` field, a `keyid` (it names a secret key krypto does
/// not have), and parameters outside the accepted range. The ceiling is the
/// `High` preset plus a margin (m + 25 %, t + 1, p + 1), so a stored string
/// cannot make one call use much more memory or time than krypto's own hashes
/// do. The messages say which field is refused, and never carry the salt or
/// the hash; a refused algorithm is named, and the parser admits there only
/// the letters a to z in lower case, digits and hyphens, at most 32 characters.
fn check_stored_hash(parsed: &PasswordHash) -> Result<(), Error> {
    if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str() {
        return Err(Error::Format(format!(
            "PHC algorithm {} is not accepted, only argon2id",
            parsed.algorithm.as_str()
        )));
    }
    match parsed.version {
        Some(v) if v == u32::from(Version::V0x13) => {}
        Some(v) => {
            return Err(Error::Format(format!(
                "argon2 version {v} is not accepted, only 19"
            )))
        }
        None => {
            return Err(Error::Format(
                "PHC string has no version field, v=19 is required".to_string(),
            ))
        }
    }
    if parsed.params.get_str("keyid").is_some() {
        return Err(Error::Format(
            "the PHC string names a secret key (keyid); krypto cannot verify it".to_string(),
        ));
    }
    let params = Params::try_from(parsed)
        .map_err(|e| Error::Format(format!("invalid argon2 parameters: {e}")))?;
    let high = Preset::High.params();
    let max_m_kib = high.m_cost().saturating_add(high.m_cost() / 4);
    let max_t = high.t_cost().saturating_add(1);
    let max_p = high.p_cost().saturating_add(1);
    let ranges = [
        ("m", params.m_cost(), MIN_M_KIB..=max_m_kib),
        ("t", params.t_cost(), MIN_T..=max_t),
        ("p", params.p_cost(), MIN_P..=max_p),
    ];
    for (name, value, range) in ranges {
        if !range.contains(&value) {
            return Err(Error::Format(format!(
                "argon2 parameter {name}={value} is outside the accepted range {}..={}",
                range.start(),
                range.end()
            )));
        }
    }
    Ok(())
}

/// Verify a password against a PHC string (constant-time). `Ok(())` on match;
/// `Error::Auth` when it does not match: a wrong password, or a PHC string that
/// parses but was cut short or altered. `Error::Format` on a PHC string that
/// cannot be parsed or is foreign (e.g. a scrypt hash or unknown params) — so a
/// hash krypto cannot check is not misdiagnosed as "wrong password".
///
/// Only what krypto makes or can make is accepted (0.8.2): Argon2id, version
/// 19 with the `v=19` field present, `65 536 ≤ m ≤ 327 680` KiB, `2 ≤ t ≤ 5`
/// and `1 ≤ p ≤ 5`. The ceiling is [`Preset::High`] plus a margin (m + 25 %,
/// t + 1, p + 1) and moves with it. Associated data (`data=`) is accepted and
/// used. Anything else, such as Argon2i, Argon2d, version 16, a `keyid` (a
/// secret key krypto does not have) or parameters outside that range, is
/// `Error::Format`, refused before argon2 runs.
///
/// `password` is at most [`MAX_PASSWORD_BYTES`] and `phc` at most
/// [`MAX_PHC_BYTES`]; a longer one is `Error::Format`, checked in that order,
/// before `phc` is parsed (0.9.0).
pub fn verify(password: &SecretString, phc: &str) -> Result<(), Error> {
    use argon2::password_hash::Error as PhError;

    check_password_len(password)?;
    if phc.len() > MAX_PHC_BYTES {
        return Err(Error::Format(format!(
            "PHC string is {} bytes — max {MAX_PHC_BYTES}",
            phc.len()
        )));
    }
    let parsed =
        PasswordHash::new(phc).map_err(|e| Error::Format(format!("invalid PHC string: {e}")))?;
    check_stored_hash(&parsed)?;
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

/// The working memory Argon2 fills during one [`derive_key`] call (0.9.0).
/// krypto holds it so that `Drop` can overwrite every block with zeros before
/// it is released, on every way out, an unwinding panic included.
struct WorkingMemory(Vec<Block>);

impl WorkingMemory {
    /// Reserves `count` blocks, all zero. Memory that cannot be had is
    /// `Error::Hardening`; the message carries only the size.
    fn new(count: usize) -> Result<Self, Error> {
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(count).map_err(|_| {
            Error::Hardening(format!(
                "cannot allocate {} bytes for argon2 working memory",
                count.saturating_mul(Block::SIZE)
            ))
        })?;
        blocks.resize(count, Block::new());
        Ok(WorkingMemory(blocks))
    }
}

impl Drop for WorkingMemory {
    fn drop(&mut self) {
        // Wipes every block and the spare capacity, so the whole allocation is
        // zero when it is released.
        self.0.zeroize();
    }
}

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
/// Must be at least 16 bytes and at most [`MAX_DERIVE_INPUT_BYTES`] (1024)
/// bytes (0.8.2); a salt outside that is `Error::Format`. It is stored in
/// plaintext next to the ciphertext. It is not a secret — its job is to make
/// precomputed tables useless, and it does that just as well in the open.
///
/// # The password
///
/// At most [`MAX_PASSWORD_BYTES`]; a longer one is `Error::Format`, checked
/// before the salt and before Argon2 runs (0.9.0).
///
/// # The working memory
///
/// The working memory Argon2 uses is held by this function and overwritten
/// with zeros before it is released (0.9.0). When that memory cannot be had,
/// the answer is `Error::Hardening`.
pub fn derive_key(
    password: &SecretString,
    salt: &[u8],
    preset: Preset,
) -> Result<crate::secret::SecretBuf, Error> {
    check_password_len(password)?;
    if salt.len() < 16 {
        return Err(Error::Format(format!(
            "argon2 salt must be at least 16 bytes, got {}",
            salt.len()
        )));
    }
    if salt.len() > MAX_DERIVE_INPUT_BYTES {
        return Err(Error::Format(format!(
            "argon2 salt must be at most {MAX_DERIVE_INPUT_BYTES} bytes, got {}",
            salt.len()
        )));
    }
    let mut memory = WorkingMemory::new(preset.params().block_count())?;
    // The key is written straight into locked memory (0.7.2).
    let res = crate::secret::SecretBuf::fill_with(32, |out| {
        password.expose_str(|pw| {
            hasher(preset)
                .hash_password_into_with_memory(pw.as_bytes(), salt, out, &mut memory.0)
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
    fn too_long_salt_is_rejected() {
        let at_cap = vec![b's'; MAX_DERIVE_INPUT_BYTES];
        let over = vec![b's'; MAX_DERIVE_INPUT_BYTES + 1];
        assert!(derive_key(&pw("x"), &at_cap, Preset::Interactive).is_ok());
        assert!(matches!(
            derive_key(&pw("x"), &over, Preset::Interactive),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn key_is_32_bytes() {
        let k = derive_key(&pw("x"), SALT, Preset::Interactive).unwrap();
        k.expose(|b| assert_eq!(b.len(), 32));
    }
}
