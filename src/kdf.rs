// SPDX-License-Identifier: MIT OR Apache-2.0
//! Master key and key derivation (HKDF-SHA256).
//!
//! The master key comes from OUTSIDE krypto (Docker secret / passphrase). It is
//! never used directly on data — only to derive purpose-specific working keys.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::Error;
use crate::secret::SecretBuf;

/// Upper bound on a master-key file. A key is 32–64 bytes; 4 KiB is generous
/// slack and prevents OOM on `/dev/zero`/a bloated file (bounded input).
pub const MAX_MASTER_KEY_BYTES: usize = 4096;

/// Upper bound on `info` and `salt` handed to [`MasterKey::derive`].
///
/// Bounded input is the rule across the crate — `from_secret_file`,
/// `SecretStore::open` and the CLI's stdin all have a cap. `derive` did not,
/// so a value arriving from a command line or a config file could be any
/// length. The longest real `info` is the store's `krypto/store/v1|` prefix
/// plus a key name: 16 + 512 bytes. The cap keeps ample room over that.
pub const MAX_DERIVE_INPUT_BYTES: usize = 1024;

/// The root key (KEK). Injected from outside; derives DEKs via HKDF.
pub struct MasterKey {
    key: SecretBuf,
}

impl MasterKey {
    /// From a key already in memory — typically derived from a password with
    /// [`crate::password::derive_key`].
    ///
    /// Exists because unlock of data at rest (SIKKERHETSMODELL §8) takes the
    /// root from a **human**, not from a file on the same disk as the
    /// ciphertext. A file next to what it locks is obfuscation, not protection.
    pub fn from_bytes(key: SecretBuf) -> Result<Self, Error> {
        let len = key.expose(|b| b.len());
        if len < 32 {
            return Err(Error::Format(format!(
                "master key must be at least 32 bytes, got {len}"
            )));
        }
        // The same cap `from_secret_file` applies: two ways into one type must
        // not mean two different rules about what the type accepts.
        if len > MAX_MASTER_KEY_BYTES {
            return Err(Error::Format(format!(
                "master key is {len} bytes — max {MAX_MASTER_KEY_BYTES}"
            )));
        }
        Ok(Self { key })
    }

    /// Read the master key (raw bytes) from a file (typically a Docker secret,
    /// mode 400). Requires 32..=`MAX` bytes. The upper cap (`MAX_MASTER_KEY_BYTES`)
    /// prevents a symlink to `/dev/zero` or a bloated file from causing unbounded
    /// allocation/OOM (bounded input) — never reads past the cap.
    pub fn from_secret_file(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        use std::io::Read;
        let f = std::fs::File::open(path)?;
        // Read up to MAX+1 to detect "too big" without reading an enormous file.
        let mut bytes = Vec::new();
        f.take(MAX_MASTER_KEY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() < 32 {
            let n = bytes.len();
            bytes.zeroize();
            return Err(Error::Format(format!(
                "master key must be at least 32 bytes, got {n}"
            )));
        }
        if bytes.len() > MAX_MASTER_KEY_BYTES {
            bytes.zeroize();
            return Err(Error::Format(format!(
                "master key file is too big (> {MAX_MASTER_KEY_BYTES} bytes)"
            )));
        }
        let key = SecretBuf::from_vec(bytes)?;
        Ok(MasterKey { key })
    }

    /// Derive a 256-bit working key for a named context.
    ///
    /// `info` is a consumer-chosen context string (krypto does not know the
    /// purpose names); `salt` is per store/context (not secret).
    pub fn derive(&self, info: &[u8], salt: &[u8]) -> Result<DerivedKey, Error> {
        // `info` is the entire purpose separation in HKDF: it is what makes the
        // audit-MAC key and the token-sealing key different. If it is empty,
        // the separation vanishes — two different purposes get the **same**
        // derived key, without a peep. That is one of those failures that is
        // impossible to see after the fact, so it must not be able to happen.
        //
        // Realistic path in: a missing config value, and a caller passing `""`
        // along without noticing.
        if info.is_empty() {
            return Err(Error::Hardening(
                "empty `info` passed to derive() — the HKDF purpose separation vanishes, \
                 and two different purposes would get the same key"
                    .into(),
            ));
        }
        // Bounded input, the same rule as everywhere else in the crate. These
        // values reach the API from command lines and config files, and an
        // unbounded one is work an attacker chooses the size of.
        for (what, len) in [("info", info.len()), ("salt", salt.len())] {
            if len > MAX_DERIVE_INPUT_BYTES {
                return Err(Error::Format(format!(
                    "`{what}` passed to derive() is {len} bytes — max {MAX_DERIVE_INPUT_BYTES}"
                )));
            }
        }
        self.key.expose(|ikm| {
            let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
            let mut okm = vec![0u8; 32];
            let res = hk
                .expand(info, &mut okm)
                .map_err(|_| Error::Hardening("HKDF expand failed".into()));
            match res {
                Ok(()) => SecretBuf::from_vec(okm).map(|dk| DerivedKey { key: dk }),
                Err(e) => {
                    okm.zeroize();
                    Err(e)
                }
            }
        })
    }
}

/// HMAC-SHA256 over `data` with a derived key — an audit chain's MAC, say.
/// Keyed MAC, not a plain hash, so someone who can edit the data
/// cannot simply recompute the chain without the key.
pub fn hmac_sha256(key: &DerivedKey, data: &[u8]) -> Result<[u8; 32], Error> {
    use hmac::{Hmac, Mac};
    key.with_key(|k| {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(k)
            .map_err(|_| Error::Hardening("invalid HMAC key length".into()))?;
        mac.update(data);
        let out = mac.finalize().into_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Ok(arr)
    })?
}

/// A derived 256-bit working key (DEK). Used only by the AEAD layer.
pub struct DerivedKey {
    key: SecretBuf,
}

impl DerivedKey {
    /// Internal: run `f` with the key as `[u8; 32]`. Fails if the length is not 32.
    pub(crate) fn with_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Error> {
        self.key.expose(|b| {
            let arr: &[u8; 32] = b
                .try_into()
                .map_err(|_| Error::Hardening("derived key must be 32 bytes".into()))?;
            Ok(f(arr))
        })
    }
}
