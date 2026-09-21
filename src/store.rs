//! `SecretStore` — encrypted key-value store on file.
//!
//! Every value is encrypted with a **per-key-name** derived DEK
//! (`HKDF(master, salt, info = "krypto/store/v1|" + name)`). That binds the
//! value to its name: a blob cannot be moved to another name without `open`
//! failing with `Auth`. Key names are plaintext (addresses, not secrets).
//! Writes are atomic (tmp + fsync + rename), file mode 0600.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::aead::{self, Alg};
use crate::error::Error;
use crate::kdf::{DerivedKey, MasterKey};
use crate::secret::SecretBuf;

const STORE_MAGIC: &[u8; 4] = b"FST1";
const STORE_VER: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_ID_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + KEY_ID_LEN;

/// Upper bound on a store file. The store holds small secrets (keys/tokens);
/// 16 MiB is very generous and prevents OOM on a tampered/bloated file
/// (bounded input).
pub const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum length of a key name in the store.
const MAX_NAME_LEN: usize = 512;

/// Validate a key name: non-empty, bounded, printable ASCII only.
///
/// Printable ASCII (`[\x20-\x7e]`): names are listed back out through `list()`
/// and may end up in a consumer's log, so a control character has no business
/// in one.
fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::Format("key name is empty".into()));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Error::Format(format!(
            "key name is {} bytes — max {MAX_NAME_LEN}",
            name.len()
        )));
    }
    if let Some(c) = name.chars().find(|&c| !(' '..='~').contains(&c)) {
        return Err(Error::Format(format!(
            "key name contains the illegal character {c:?} — printable ASCII only, \
             because names are listed out and may end up in a log"
        )));
    }
    Ok(())
}

/// File-based, encrypted KV store. The master key is borrowed for the store's lifetime.
pub struct SecretStore<'a> {
    path: PathBuf,
    master: &'a MasterKey,
    salt: [u8; SALT_LEN],
    key_id: [u8; KEY_ID_LEN],
    entries: HashMap<String, Vec<u8>>, // name -> FAFN blob
}

impl<'a> SecretStore<'a> {
    /// Open an existing store, or create a new one if the file is missing.
    ///
    /// Distinguishes `ErrorKind::NotFound` — any other I/O error (permission,
    /// ELOOP, …) is propagated instead of being treated as "empty store", so we
    /// never rename a fresh empty store over an existing one we simply failed
    /// to read.
    pub fn open(path: impl AsRef<Path>, master: &'a MasterKey) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        match read_capped(&path, MAX_STORE_BYTES)? {
            Some(data) => Self::load(path, master, &data),
            None => {
                // The file does not exist → create a new, empty store.
                let mut salt = [0u8; SALT_LEN];
                let mut key_id = [0u8; KEY_ID_LEN];
                getrandom::getrandom(&mut salt)
                    .map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
                getrandom::getrandom(&mut key_id)
                    .map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
                let store = SecretStore {
                    path,
                    master,
                    salt,
                    key_id,
                    entries: HashMap::new(),
                };
                store.persist()?;
                Ok(store)
            }
        }
    }

    /// Store a secret under `name` (overwrites an existing one).
    ///
    /// The name is validated on **character set and length**, not just length.
    /// Names are not secret and are exposed through [`SecretStore::list`] — a
    /// name with a newline could shift lines in a consumer's log, and an empty
    /// name is not a key anyone can look up again.
    pub fn put(&mut self, name: &str, secret: &SecretBuf) -> Result<(), Error> {
        validate_name(name)?;
        let dek = self.dek_for(name)?;
        let blob = aead::seal(&dek, &self.key_id, secret, Alg::Aegis256)?;
        // Persist BEFORE memory and disk can diverge: if persist fails, roll
        // back the insert so a later `get` cannot return a value that was
        // never stored.
        let previous = self.entries.insert(name.to_string(), blob);
        if let Err(e) = self.persist() {
            match previous {
                Some(old) => {
                    self.entries.insert(name.to_string(), old);
                }
                None => {
                    self.entries.remove(name);
                }
            }
            return Err(e);
        }
        Ok(())
    }

    /// Fetch a secret. `KeyNotFound` if the name does not exist.
    ///
    /// If the stored blob was sealed under a different master-key generation
    /// than this store's, the result is [`Error::WrongKey`] — a routing
    /// outcome, not tampering (0.5.0; before that it surfaced as `Auth`, which
    /// consumers alarm on).
    pub fn get(&self, name: &str) -> Result<SecretBuf, Error> {
        let blob = self.entries.get(name).ok_or(Error::KeyNotFound)?;
        // The key_id is an unauthenticated hint (it is AAD, verified by `open`):
        // it can only steer towards the honest "wrong generation" answer, never
        // away from `Auth` — a forged key_id fails `open` regardless.
        if aead::blob_key_id(blob)? != self.key_id {
            return Err(Error::WrongKey);
        }
        let dek = self.dek_for(name)?;
        aead::open(&dek, blob)
    }

    /// Delete a secret. Not an error if the name does not exist.
    pub fn delete(&mut self, name: &str) -> Result<(), Error> {
        if let Some(old) = self.entries.remove(name) {
            if let Err(e) = self.persist() {
                self.entries.insert(name.to_string(), old); // roll back on persist failure
                return Err(e);
            }
        }
        Ok(())
    }

    /// Whether a name exists (without decrypting).
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Sorted key names with the given prefix (names are not secret).
    pub fn list(&self, prefix: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .entries
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Re-encrypt the whole store under a new master key — the rotation
    /// *action* (0.6.0). krypto is stateless: both keys come from the caller,
    /// which owns when and why a rotation happens.
    ///
    /// Consumes the store (it is bound to the old master's lifetime) and
    /// returns a new handle bound to `new_master`, with a fresh salt and a
    /// fresh key-generation id. Everything is decrypted with the old master
    /// FIRST — if any entry fails ([`Error::Auth`] on a wrong old key or
    /// tampering), nothing is written and the file is untouched. The file
    /// then flips old → new in one atomic rename: never a half-rotated store.
    ///
    /// The handle is consumed even on failure (a stale handle over a replaced
    /// file could persist old-generation data back over the new one) — on
    /// error, reopen the file; it is unchanged.
    ///
    /// A store file that was rotated away from an old master fails `get` with
    /// [`Error::Auth`] under that master (the per-name DEKs no longer match).
    /// [`Error::WrongKey`] remains the signal for a *mixed-generation blob
    /// inside* a store, not for opening a store with the wrong master.
    pub fn rotate<'b>(self, new_master: &'b MasterKey) -> Result<SecretStore<'b>, Error> {
        // 1. Decrypt everything with the old master before anything is written.
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        let mut plain = Vec::with_capacity(names.len());
        for name in names {
            let secret = self.get(&name)?;
            plain.push((name, secret));
        }

        // 2. Build the new generation in memory.
        let mut salt = [0u8; SALT_LEN];
        let mut key_id = [0u8; KEY_ID_LEN];
        getrandom::getrandom(&mut salt).map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
        getrandom::getrandom(&mut key_id)
            .map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
        let mut new_store = SecretStore {
            path: self.path.clone(),
            master: new_master,
            salt,
            key_id,
            entries: HashMap::new(),
        };
        for (name, secret) in &plain {
            let dek = new_store.dek_for(name)?;
            let blob = aead::seal(&dek, &new_store.key_id, secret, Alg::Aegis256)?;
            new_store.entries.insert(name.clone(), blob);
        }

        // 3. One atomic write replaces the file.
        new_store.persist()?;
        Ok(new_store)
    }

    // --- internal ---

    fn dek_for(&self, name: &str) -> Result<DerivedKey, Error> {
        let mut info = Vec::with_capacity(16 + name.len());
        info.extend_from_slice(b"krypto/store/v1|");
        info.extend_from_slice(name.as_bytes());
        self.master.derive(&info, &self.salt)
    }

    fn load(path: PathBuf, master: &'a MasterKey, data: &[u8]) -> Result<Self, Error> {
        if data.len() < HEADER_LEN {
            return Err(Error::Format("store header truncated".into()));
        }
        if &data[0..4] != STORE_MAGIC {
            return Err(Error::Format("wrong store magic".into()));
        }
        if data[4] != STORE_VER {
            return Err(Error::Format(format!(
                "unsupported store version {}",
                data[4]
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[5..5 + SALT_LEN]);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&data[5 + SALT_LEN..HEADER_LEN]);

        let mut entries = HashMap::new();
        let mut off = HEADER_LEN;
        while off < data.len() {
            if off + 2 > data.len() {
                return Err(Error::Format("store truncated (name length)".into()));
            }
            let nlen = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
            off += 2;
            // checked_add: a tampered/corrupt file could otherwise wrap off+len
            // and make the bounds check falsely pass → panic in the slice below.
            match off.checked_add(nlen) {
                Some(end) if end <= data.len() => {}
                _ => return Err(Error::Format("store truncated (name)".into())),
            }
            let name = String::from_utf8(data[off..off + nlen].to_vec())
                .map_err(|_| Error::Format("invalid UTF-8 in key name".into()))?;
            // The same fence as `put`. Without it the rule holds only for what
            // THIS process wrote: a corrupt or tampered file could carry a name
            // with a newline straight out through `list()`, which is documented
            // as ending up in a consumer's log.
            validate_name(&name)?;
            off += nlen;
            if off + 4 > data.len() {
                return Err(Error::Format("store truncated (blob length)".into()));
            }
            let blen = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                as usize;
            off += 4;
            match off.checked_add(blen) {
                Some(end) if end <= data.len() => {}
                _ => return Err(Error::Format("store truncated (blob)".into())),
            }
            if entries
                .insert(name, data[off..off + blen].to_vec())
                .is_some()
            {
                return Err(Error::Format("duplicate key name in store".into()));
            }
            off += blen;
        }
        Ok(SecretStore {
            path,
            master,
            salt,
            key_id,
            entries,
        })
    }

    fn persist(&self) -> Result<(), Error> {
        let mut buf = Vec::new();
        buf.extend_from_slice(STORE_MAGIC);
        buf.push(STORE_VER);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.key_id);
        let mut names: Vec<&String> = self.entries.keys().collect();
        names.sort(); // deterministic file
        for name in names {
            let blob = &self.entries[name];
            let blen = u32::try_from(blob.len())
                .map_err(|_| Error::Format("blob too big for the store format".into()))?;
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&blen.to_le_bytes());
            buf.extend_from_slice(blob);
        }
        atomic_write(&self.path, &buf)
    }
}

/// Read a file with an upper size cap. `Ok(None)` = the file does not exist
/// (the caller creates a new store); `Ok(Some(bytes))` = contents within the
/// cap; `Err(Format)` = too big (bounded input, no OOM); other I/O errors → `Err(Io)`.
fn read_capped(path: &Path, cap: usize) -> Result<Option<Vec<u8>>, Error> {
    use std::io::Read;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    let mut bytes = Vec::new();
    f.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(Error::Format(format!(
            "store file is too big (> {cap} bytes)"
        )));
    }
    Ok(Some(bytes))
}

/// Write `data` atomically to `path` (tmp + fsync + rename), mode 0600 (unix).
///
/// The tmp file is created **with** 0600 (unix) — not chmod'ed afterwards — so
/// there is never a window where it is world-readable. On any failure before
/// the rename the tmp file is removed, so an aborted write leaves no `.tmp-*`
/// files behind.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), Error> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("store");
    let tmp = dir.join(format!(".tmp-{}-{fname}", std::process::id()));

    let result = write_tmp_then_rename(&tmp, path, data);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp); // clean up a half-written tmp
    }
    result
}

fn write_tmp_then_rename(tmp: &Path, path: &Path, data: &[u8]) -> Result<(), Error> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)?;
    Ok(())
}
